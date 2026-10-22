#!/usr/bin/env python3
"""Disable Ethernet takeover and verify the household gateway is restored."""

import configparser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


CONFIG = Path("/etc/freebox_ethernet.conf")
SERVICE = "freebox_ethernet.service"
TABLE = "4242"
PRIORITY = "10424"
NFT_TABLE = "freebox_ethernet"


def run(*arguments):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} exited with status {result.returncode}")
    return result.stdout


def disable_takeover():
    settings = configparser.ConfigParser(interpolation=None)
    if not settings.read(CONFIG) or not settings.has_section("ethernet"):
        raise RuntimeError("Failover configuration is unreadable")
    settings.set("ethernet", "enabled", "false")
    descriptor, temporary = tempfile.mkstemp(prefix=".freebox_ethernet.", dir=CONFIG.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            settings.write(output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, CONFIG)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def verify_restored():
    settings = configparser.ConfigParser(interpolation=None)
    settings.read(CONFIG)
    if settings.getboolean("ethernet", "enabled", fallback=True):
        raise RuntimeError("Takeover remains enabled")
    status = json.loads(run("python3", "/opt/freebox-failover/freebox_ethernet.py", "--status"))
    if status.get("mode") != "monitor-only" or status.get("active") is not False or status.get("stale"):
        raise RuntimeError("Monitor-only service postcondition failed")
    rules = json.loads(run("ip", "-j", "-4", "rule", "show"))
    if any(str(rule.get("priority")) == PRIORITY or str(rule.get("table")) == TABLE
           or str(rule.get("fwmark")) in ("0x4242", str(int("0x4242", 16))) for rule in rules):
        raise RuntimeError("Failover policy rule remains installed")
    routes = run("ip", "-4", "route", "show", "table", TABLE)
    if routes.strip():
        raise RuntimeError("Failover route table is not empty")
    tables = json.loads(run("nft", "-j", "list", "tables"))
    if any(entry.get("table", {}).get("family") == "ip"
           and entry.get("table", {}).get("name") == NFT_TABLE
           for entry in tables.get("nftables", [])):
        raise RuntimeError("Failover firewall table remains installed")
    defaults = json.loads(run("ip", "-j", "-4", "route", "show", "default"))
    if not any(route.get("gateway") == "192.168.1.254" for route in defaults):
        raise RuntimeError("VM default route is not restored through the Freebox")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    disable_takeover()
    run("systemctl", "restart", SERVICE)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            run("systemctl", "is-active", SERVICE)
            verify_restored()
            print("Takeover disabled; monitor-only service and Freebox routes verified")
            return 0
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError):
            time.sleep(1)
    raise SystemExit("Rollback verification did not complete within 45 seconds")


if __name__ == "__main__":
    sys.exit(main())
