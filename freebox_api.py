"""Shared Freebox authentication and private token storage."""

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

import requests


APP_ID = "free_wifi_gateway"
APP_NAME = "Freebox Failover"
VERSION = "0.1.0"


class ApiError(RuntimeError):
    def __init__(self, code, endpoint=""):
        self.code = code
        super().__init__(f"Freebox API {code}" + (f" at {endpoint}" if endpoint else ""))


def load_token(filename):
    try:
        with open(filename, encoding="utf-8") as source:
            permissions = os.fstat(source.fileno())
            if not stat.S_ISREG(permissions.st_mode):
                raise ApiError("token_not_regular_file")
            if os.name == "posix" and stat.S_IMODE(permissions.st_mode) & 0o077:
                raise ApiError("token_permissions_require_0600")
            data = json.load(source)
        if not isinstance(data, dict):
            raise ValueError
        token = data["app_token"]
        track_id = data["track_id"]
        if not isinstance(token, str) or not token or isinstance(track_id, bool):
            raise ValueError
        if not isinstance(track_id, (str, int)) or not str(track_id).isdigit():
            raise ValueError
        return token, int(track_id)
    except FileNotFoundError as error:
        raise ApiError("token_missing") from error
    except (ValueError, KeyError, TypeError) as error:
        raise ApiError("token_invalid") from error
    except OSError as error:
        raise ApiError("token_unreadable") from error


def save_token(filename, token, track_id):
    destination = Path(filename)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump({"app_token": token, "track_id": track_id}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


class FreeboxClient:
    def __init__(self, host, token_file, expected_mac=None):
        self.host = str(ipaddress.IPv4Address(host))
        self.token_file = token_file
        self.expected_mac = expected_mac.lower() if expected_mac else None
        self.session = requests.Session()
        self.session.trust_env = False
        self.last_error = None

    def request(self, method, endpoint, **kwargs):
        try:
            response = self.session.request(method, f"http://{self.host}/api/v8{endpoint}",
                                            timeout=(2, 3), allow_redirects=False, **kwargs)
        except requests.RequestException as error:
            raise ApiError("transport_error", endpoint) from error
        try:
            data = response.json()
        except ValueError as error:
            raise ApiError("invalid_json", endpoint) from error
        if not isinstance(data, dict):
            raise ApiError("invalid_response", endpoint)
        if response.status_code >= 300 or data.get("success") is not True:
            code = data.get("error_code", f"http_{response.status_code}")
            if not isinstance(code, str) or not re.fullmatch(r"[a-z_0-9]{1,64}", code):
                code = "request_rejected"
            raise ApiError(code, endpoint)
        if not isinstance(data.get("result"), dict):
            raise ApiError("invalid_result", endpoint)
        return data["result"]

    def login(self):
        self.session.headers.pop("X-Fbx-App-Auth", None)
        token, track_id = load_token(self.token_file)
        result = self.request("GET", f"/login/authorize/{track_id}")
        challenge = result.get("challenge")
        if not isinstance(challenge, str) or not challenge:
            raise ApiError("challenge_missing")
        password = hmac.new(token.encode(), challenge.encode(), hashlib.sha1).hexdigest()
        result = self.request("POST", "/login/session/", json={"app_id": APP_ID, "password": password})
        session_token = result.get("session_token")
        if not isinstance(session_token, str) or not session_token:
            raise ApiError("session_missing")
        self.session.headers["X-Fbx-App-Auth"] = session_token
        if self.expected_mac:
            try:
                actual_mac = self.request("GET", "/system/").get("mac")
                if not isinstance(actual_mac, str) or actual_mac.lower() != self.expected_mac:
                    raise ApiError("primary_mac_mismatch")
            except ApiError:
                self.session.headers.pop("X-Fbx-App-Auth", None)
                raise
        self.last_error = None

    def state(self):
        try:
            if "X-Fbx-App-Auth" not in self.session.headers:
                self.login()
            try:
                result = self.request("GET", "/connection/")
            except ApiError as error:
                if error.code not in ("auth_required", "invalid_session", "http_403"):
                    raise
                self.login()
                result = self.request("GET", "/connection/")
            state = result.get("state")
            if state not in ("up", "down", "going_up", "going_down"):
                raise ApiError("invalid_wan_state")
            self.last_error = None
            return state
        except ApiError as error:
            self.last_error = error.code
            return "unknown"

    def close(self):
        try:
            if "X-Fbx-App-Auth" in self.session.headers:
                self.request("POST", "/login/logout/")
        except ApiError:
            pass
        finally:
            self.session.headers.pop("X-Fbx-App-Auth", None)
            self.session.close()
