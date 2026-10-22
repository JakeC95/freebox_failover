#!/usr/bin/env python3
"""Read-only preparation checks; never enables takeover or authorizes rollout."""

import argparse
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


REMAINING_GATES = (
    "approved IPv4/IPv6 failover policy using the existing Freebox VM and cellular router",
    "measured gateway throughput and an accepted gateway/VM failure policy",
    "representative household client and application acceptance",
    "independent production rollback rehearsed for the selected topology",
    "fresh primary and cellular end-to-end acceptance with the deployment SIM",
    "explicit user-approved maintenance window and permission to activate",
)


def command(*arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} returned {result.returncode}")
    return result.stdout.strip()


def evaluate(config, status, service, disk_free, memory_available, namespaces, watchdog):
    return {
        "takeover_disabled": config.getboolean("ethernet", "enabled", fallback=True) is False,
        "ipv6_interlock_not_bypassed": config.getboolean("ethernet", "lan_ipv6_disabled", fallback=True) is False,
        "monitor_active": service == "active",
        "heartbeat_current": status.get("stale") is False,
        "monitor_only": status.get("mode") == "monitor-only" and status.get("active") is False,
        "primary_api_up": status.get("wan") == "up" and status.get("api_error") is None,
        "disk_headroom": disk_free >= 512 * 1024 * 1024,
        "memory_headroom": memory_available >= 128 * 1024 * 1024,
        "no_leftover_pilot_namespaces": not any(name.startswith(("f4g-pilot-", "f4g-bench-")) for name in namespaces),
        "systemd_watchdog_configured": watchdog.get("WatchdogUSec") not in (None, "", "0") and watchdog.get("Restart") == "on-failure",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/freebox_ethernet.conf")
    parser.add_argument("--repository", default="/opt/freebox-failover")
    parser.add_argument("--output", help="Optional NEW private JSON report file; never overwrite an existing file")
    arguments = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run on the Linux gateway as root for complete read-only inspection")
    report = {"observed_utc": datetime.now(timezone.utc).isoformat(),
              "rollout_authorized": False, "production_ready": False,
              "remaining_gates": list(REMAINING_GATES), "checks": {}}
    try:
        config = configparser.ConfigParser(interpolation=None)
        if not config.read(arguments.config):
            raise RuntimeError("Configuration unreadable")
        repository = Path(arguments.repository).resolve()
        status = json.loads(command("python3", str(repository / "freebox_ethernet.py"), "--status"))
        service = command("systemctl", "is-active", "freebox_ethernet.service")
        watchdog = dict(line.split("=", 1) for line in command(
            "systemctl", "show", "freebox_ethernet.service", "-p", "WatchdogUSec", "-p", "Restart").splitlines())
        memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        available = int(memory["MemAvailable"].split()[0]) * 1024
        free = shutil.disk_usage(repository).free
        namespaces = [line.split()[0] for line in command("ip", "netns", "list").splitlines()]
        report["checks"] = evaluate(config, status, service, free, available, namespaces, watchdog)
        report["revision"] = command("git", "-C", str(repository), "rev-parse", "HEAD")
        report["checks"]["checkout_clean"] = not command("git", "-C", str(repository), "status", "--porcelain")
        backups = Path("/var/backups/freebox-failover")
        report["checks"]["completed_install_backup_present"] = any(
            marker.is_file() and (marker.parent / "source.tar.gz").is_file()
            and (marker.parent / "etc/freebox_ethernet.conf").is_file()
            and (marker.parent / "etc/systemd/system/freebox_ethernet.service").is_file()
            for marker in backups.glob("*/COMPLETE"))
        report["resources"] = {"disk_free_bytes": free, "memory_available_bytes": available}
        report["preparation_checks_passed"] = all(report["checks"].values())
    except (OSError, ValueError, KeyError, RuntimeError, configparser.Error, subprocess.TimeoutExpired) as error:
        report["preparation_checks_passed"] = False
        report["inspection_error"] = type(error).__name__
    if arguments.output:
        destination = Path(arguments.output)
        parent = destination.parent.stat()
        if parent.st_uid != 0 or not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700:
            parser.error("Report parent must already exist, be root-owned and mode 0700")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report, indent=2))
    return 0 if report["preparation_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
