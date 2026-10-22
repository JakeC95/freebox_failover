#!/usr/bin/env python3
"""Bounded LTE-only download with concurrent DNS/HTTPS checks; never steers clients."""

import argparse
import json
import os
from pathlib import Path
import time
import uuid

import paramiko

from android_lte_pilot import backup_health, device_hash, query
from openwrt_ap_audit import private_directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--mib", type=int, choices=(1, 10), default=10)
    arguments = parser.parse_args()
    expected_bytes = arguments.mib * 1024 * 1024
    download_url = f"https://rbx.proof.ovh.net/files/{arguments.mib}Mb.dat"
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW report in an existing private directory")
    directory = "/tmp/f4g-load-" + uuid.uuid4().hex[:12]
    report = {"scope": "router-originated LTE download only; no phone/household steering", "health": [],
              "requested_bytes": expected_bytes, "download_url": download_url, "completed": False}
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output, paramiko.SSHClient() as client:
        client.load_host_keys(arguments.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(arguments.router, username="root", key_filename=arguments.key,
                       look_for_keys=False, allow_agent=False, timeout=8, banner_timeout=8, auth_timeout=8)
        configuration = device_hash(client, "inet")
        firewall = query(client, "nft -s list ruleset")[0]
        process_id = None

        def probe():
            started = time.monotonic()
            observation = {}
            try:
                previous = next((entry["result"]["uptime"] for entry in reversed(report["health"])
                                 if entry.get("healthy")), None)
                observation["result"] = backup_health(client, arguments.router, previous)
                observation["healthy"] = True
            except Exception as error:
                observation.update(healthy=False, error=type(error).__name__ + ": " + str(error))
            observation["seconds"] = round(time.monotonic() - started, 2)
            report["health"].append(observation)
            print(json.dumps(observation), flush=True)

        try:
            routes = query(client, "ip -4 route show default")[0]
            if "dev wwan0" not in routes or len(routes.strip().splitlines()) != 1:
                raise RuntimeError("An exclusively cellular default route is required")
            probe()
            if not report["health"][-1]["healthy"]:
                raise RuntimeError("Backup baseline failed; no load started")
            script = ("trap 'exit 143' TERM INT\n"
                      "worker_pid=$$\n"
                      "( sleep 45; kill -TERM -\"$worker_pid\" ) &\n"
                      "watchdog=$!\n"
                      "trap 'kill \"$watchdog\" 2>/dev/null || true' EXIT\n"
                      f"{{ uclient-fetch -4 -T 15 -O - '{download_url}' "
                      f"2>{directory}/download.log; printf '%s' \"$?\" > {directory}/exit; }} | wc -c > {directory}/bytes\n"
                      f"touch {directory}/done\n")
            query(client, f"umask 077; mkdir {directory}; cat > {directory}/load.sh", script)
            process_id = int(query(client, f"setsid sh {directory}/load.sh </dev/null >/dev/null 2>&1 & echo $!")[0])
            if process_id <= 1:
                raise RuntimeError("Invalid worker PID")
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                probe()
                if query(client, f"test -f {directory}/done", optional=True)[1] == 0:
                    break
                time.sleep(0.5)
            if query(client, f"test -f {directory}/done", optional=True)[1]:
                raise RuntimeError("Bounded download exceeded its controller deadline")
            report["download_exit"] = int(query(client, f"cat {directory}/exit")[0])
            report["received_bytes"] = int(query(client, f"cat {directory}/bytes")[0])
            report["download_diagnostics"] = query(client, f"tail -c 8192 {directory}/download.log")[0]
            for attempt in range(3):
                probe()
                time.sleep(0.5)
            report["completed"] = report["download_exit"] == 0 and report["received_bytes"] == expected_bytes
        except Exception as error:
            report["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if process_id:
                try:
                    query(client, f"if [ -r /proc/{process_id}/cmdline ] && "
                          f"tr '\\0' ' ' < /proc/{process_id}/cmdline | grep -q '{directory}/load.sh'; "
                          f"then kill -TERM -{process_id}; fi", optional=True)
                except Exception:
                    report["worker_cleanup_error"] = True
            for label, verify in (
                    ("configuration_unchanged", lambda: device_hash(client, "inet") == configuration),
                    ("firewall_unchanged", lambda: query(client, "nft -s list ruleset")[0] == firewall)):
                try:
                    report[label] = verify()
                except Exception as error:
                    report[label] = False
                    report[label + "_error"] = type(error).__name__ + ": " + str(error)
            json.dump(report, output, indent=2)
            output.write("\n")
    passed = (report["completed"] and all(entry["healthy"] for entry in report["health"])
              and report["configuration_unchanged"] and report["firewall_unchanged"]
              and not report.get("worker_cleanup_error"))
    print(json.dumps({"passed": passed, "report": str(destination), "error": report.get("error")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
