#!/usr/bin/env python3
"""Restore Freebox gateway ownership and restart the armed production service."""

import argparse
import configparser
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} exited with status {result.returncode}")
    return result.stdout.strip()


def load_controller(source, runtime):
    sys.path.insert(0, "/opt/freebox-failover")
    sys.path.insert(0, str(Path(source).resolve().parent))
    specification = importlib.util.spec_from_file_location("freebox_ethernet_lan_rollback", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.RUNTIME = Path(runtime)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--canary-unit", required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run rollback as root")

    installed = configparser.ConfigParser(interpolation=None)
    if not installed.read("/etc/freebox_ethernet.conf") or not installed.getboolean("ethernet", "enabled"):
        raise RuntimeError("Installed failover configuration is not enabled; refusing unexpected state")

    subprocess.run(["systemctl", "stop", arguments.canary_unit], check=False, timeout=30)
    module = load_controller(arguments.source, arguments.runtime)
    module.Network(module.Settings(arguments.config)).cleanup()
    run("systemctl", "start", "freebox_ethernet.service")

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            status = json.loads(run("python3", "/opt/freebox-failover/freebox_ethernet.py", "--status"))
            if (status.get("mode") == "armed" and status.get("wan") == "up"
                    and status.get("active") is False and status.get("backup_healthy") is True
                    and not status.get("stale")):
                break
        except (RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Armed production service did not become healthy after rollback")

    rules = json.loads(run("ip", "-j", "-4", "rule", "show"))
    if not any(str(rule.get("priority")) == "10424" and str(rule.get("table")) == "4242"
               for rule in rules):
        raise RuntimeError("Production standby policy rule is missing")
    routes = run("ip", "-4", "route", "show", "table", "4242")
    if "default via 192.168.1.253" not in routes:
        raise RuntimeError("Production standby route via LTE is missing")
    defaults = json.loads(run("ip", "-j", "-4", "route", "show", "default"))
    if not any(route.get("gateway") == "192.168.1.254" for route in defaults):
        raise RuntimeError("VM default route through Freebox was not restored")
    tables = json.loads(run("nft", "-j", "list", "tables"))
    if any(entry.get("table", {}).get("family") == "ip"
           and entry.get("table", {}).get("name") == "freebox_ethernet"
           for entry in tables.get("nftables", [])):
        raise RuntimeError("IPv4 takeover firewall table remains installed")
    print("Gateway ownership restored; production armed, WAN up, LTE standby healthy")


if __name__ == "__main__":
    main()
