#!/usr/bin/env python3
"""Register Freebox Failover, or verify an existing application token."""

import argparse
import configparser
import sys
import time

from freebox_api import APP_ID, APP_NAME, VERSION, ApiError, FreeboxClient, load_token, save_token


def register(client, timeout=120):
    try:
        token, track_id = load_token(client.token_file)
    except ApiError as error:
        if error.code != "token_missing":
            raise
        result = client.request("POST", "/login/authorize/", json={
            "app_id": APP_ID, "app_name": APP_NAME, "app_version": VERSION,
            "device_name": "Freebox Ultra Linux VM"})
        token, track_id = result.get("app_token"), result.get("track_id")
        if not isinstance(token, str) or not token or type(track_id) is not int or track_id < 0:
            raise ApiError("invalid_authorization_response")
        save_token(client.token_file, token, track_id)
    deadline = time.monotonic() + timeout
    while True:
        result = client.request("GET", f"/login/authorize/{track_id}")
        status = result.get("status")
        if status == "granted":
            client.login()
            return
        if status not in ("pending", "unknown"):
            raise ApiError("authorization_" + status if status in ("denied", "timeout")
                           else "authorization_invalid_status")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ApiError("authorization_timeout")
        print("Approve the application on the Freebox front panel.", flush=True)
        time.sleep(min(2, remaining))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="/etc/freebox_failover.conf")
    parser.add_argument("-t", "--token-file")
    parser.add_argument("--check-existing", action="store_true",
                        help="Verify the saved token without requesting a new authorization")
    args = parser.parse_args(argv)
    client = None
    try:
        config = configparser.ConfigParser(interpolation=None)
        if not config.read(args.config):
            raise ValueError("Configuration file is missing")
        token_file = args.token_file or config.get("freebox", "token_file")
        client = FreeboxClient(config.get("freebox", "ip"), token_file)
        if args.check_existing:
            client.login()
        else:
            register(client)
        print("Freebox authorization verified. Token remains private.")
        return 0
    except (ApiError, OSError, ValueError, configparser.Error) as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
