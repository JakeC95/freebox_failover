#!/usr/bin/env python3
"""Bounded, MAC-scoped IPv6-loss observation on OpenWrt access points."""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
import uuid

import paramiko

from openwrt_ap_audit import private_directory


def query(client, command, payload=None, optional=False):
    stdin, stdout, stderr = client.exec_command(command, timeout=15)
    if payload is not None:
        stdin.write(payload)
    stdin.channel.shutdown_write()
    output = stdout.read(262145)
    errors = stderr.read(8192)
    status = stdout.channel.recv_exit_status()
    if len(output) > 262144:
        raise RuntimeError("AP response exceeded its bound")
    if status and not optional:
        program = command.split(maxsplit=1)[0]
        raise RuntimeError(f"Remote command {program} failed (exit {status}): " + errors.decode().strip())
    return output.decode(), status


def configuration_hash(client):
    output, unused = query(client, "sha256sum /etc/config/network /etc/config/wireless /etc/config/dhcp")
    return hashlib.sha256(output.encode()).hexdigest()


def discover(client, mac):
    output, unused = query(client, "ubus list 'hostapd.*'")
    interfaces, associated = [], []
    for service in output.split():
        interface = service.removeprefix("hostapd.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", interface):
            raise ValueError("Unsafe wireless interface")
        output, unused = query(client, "ubus call " + shlex.quote(service) + " get_clients")
        clients = json.loads(output).get("clients", {})
        interfaces.append(interface)
        for address, details in clients.items():
            if address.lower() == mac and details.get("authorized"):
                associated.append({"interface": interface, "signal_dbm": details.get("signal")})
    if not interfaces:
        raise RuntimeError("No hostapd interfaces found")
    return interfaces, associated


def ruleset(table, interfaces, mac, drop):
    lines = [f"table netdev {table} {{"]
    for index, interface in enumerate(interfaces):
        lines.extend([
            f" chain wifi{index} {{",
            f'  type filter hook ingress device "{interface}" priority -500; policy accept;',
            f"  ether saddr {mac} ether type ip counter;",
            f"  ether saddr {mac} ether type ip6 ip6 daddr 2000::/3 counter" + (" drop;" if drop else ";"),
            " }",
        ])
    return "\n".join(lines + ["}", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--report", required=True, help="NEW file in an existing private directory")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--mode", choices=("observe", "drop"), default="observe")
    parser.add_argument("--run", action="store_true", help="Otherwise only perform read-only checks and nft validation")
    parser.add_argument("--confirm-cellular-off", action="store_true")
    arguments = parser.parse_args()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", arguments.mac) or int(arguments.mac[:2], 16) & 1 or arguments.mac == "00:00:00:00:00:00":
        parser.error("Use a nonzero lowercase unicast MAC")
    if not 5 <= arguments.seconds <= 180:
        parser.error("Duration must be 5..180 seconds")
    if len(set(arguments.host)) != len(arguments.host):
        parser.error("Duplicate AP host")
    if arguments.run and arguments.mode == "drop" and not arguments.confirm_cellular_off:
        parser.error("Confirm the phone's mobile data is off before a disruptive test")
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW report in an existing private directory")
    table = "f4g_phone_" + uuid.uuid4().hex[:12]
    directory = "/tmp/" + table
    report = {"scope": "phone-only public IPv6 loss; IPv4 remains on fibre, NOT a 4G test",
              "target_mac": arguments.mac, "mode": arguments.mode,
              "seconds": arguments.seconds, "ap": {}, "completed": False}
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output, ExitStack() as stack:
        clients, armed = {}, []
        try:
            for host in arguments.host:
                client = stack.enter_context(paramiko.SSHClient())
                client.load_host_keys(arguments.known_hosts)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect(host, username="root", password=os.environ["FAILSAFE_AP_PASSWORD"],
                               look_for_keys=False, allow_agent=False, timeout=8, banner_timeout=8, auth_timeout=8)
                clients[host] = client
                interfaces, associated = discover(client, arguments.mac)
                baseline, unused = query(client, "nft -s list ruleset")
                if "f4g_phone_" in baseline:
                    raise RuntimeError("Another phone test is present")
                query(client, "command -v setsid >/dev/null")
                rules = ruleset(table, interfaces, arguments.mac, arguments.mode == "drop")
                query(client, "nft -c -f -", rules)
                report["ap"][host] = {"interfaces": interfaces, "associated_before": associated,
                                      "configuration_before": configuration_hash(client),
                                      "ruleset_before": baseline, "rules": rules}
            if not any(data["associated_before"] for data in report["ap"].values()):
                raise RuntimeError("Target is not associated with any supplied AP")
            if arguments.run:
                for host, client in clients.items():
                    guard = ("trap '' HUP\n"
                             f"trap 'nft delete table netdev {table} 2>/dev/null' EXIT\n"
                             f"nft -f {directory}/rules.nft || exit 1\n"
                             f"date +%s > {directory}/ready\n"
                             f"sleep {arguments.seconds}\n"
                             f"nft delete table netdev {table} 2>/dev/null\n"
                             f"date +%s > {directory}/expired\n")
                    query(client, f"umask 077; mkdir {directory}; cat > {directory}/rollback.sh", guard)
                    query(client, f"umask 077; cat > {directory}/rules.nft", report["ap"][host]["rules"])
                    armed.append(host)
                    query(client, f"setsid sh {directory}/rollback.sh </dev/null >{directory}/guard.log 2>&1 &\n"
                          f"for attempt in 1 2 3 4 5; do test -f {directory}/ready && exit 0; sleep 1; done; exit 1")
                print(json.dumps({"active": True, "mode": arguments.mode, "seconds": arguments.seconds,
                                  "scope": report["scope"]}), flush=True)
                deadline = time.monotonic() + arguments.seconds
                while time.monotonic() < deadline:
                    time.sleep(min(5, max(0, deadline - time.monotonic())))
                    counters = {}
                    for host, client in clients.items():
                        listing, status = query(client, f"nft -j list table netdev {table}", optional=True)
                        if not status:
                            rules = json.loads(listing)["nftables"]
                            entries = [entry["rule"] for entry in rules if "rule" in entry]
                            report["ap"][host]["last_counters"] = entries
                            totals = {"ipv4_packets": 0, "public_ipv6_packets": 0}
                            for entry in entries:
                                family = "public_ipv6_packets" if any(
                                    expression.get("match", {}).get("left", {}).get("payload", {}).get("protocol") == "ip6"
                                    for expression in entry["expr"]) else "ipv4_packets"
                                totals[family] += sum(expression.get("counter", {}).get("packets", 0)
                                                      for expression in entry["expr"])
                            counters[host] = totals
                    print(json.dumps({"elapsed_scope": arguments.mode, "counters": counters}), flush=True)
                for host, client in clients.items():
                    for attempt in range(8):
                        expired, status = query(client, f"test -f {directory}/expired", optional=True)
                        if not status:
                            break
                        time.sleep(0.5)
                    listing, present = query(client, f"nft list table netdev {table}", optional=True)
                    report["ap"][host]["independent_expiry_verified"] = not status and present != 0
                    if not report["ap"][host]["independent_expiry_verified"]:
                        raise RuntimeError("Independent expiration was not confirmed")
            report["completed"] = True
        except (Exception, KeyboardInterrupt) as error:
            report["error"] = type(error).__name__ + ": " + str(error)
        finally:
            for host in armed:
                try:
                    query(clients[host], f"nft delete table netdev {table}", optional=True)
                except Exception:
                    report["ap"][host]["cleanup_error"] = True
            for host, data in report["ap"].items():
                try:
                    data["configuration_unchanged"] = configuration_hash(clients[host]) == data["configuration_before"]
                    current, unused = query(clients[host], "nft -s list ruleset")
                    data["ruleset_restored"] = current == data["ruleset_before"]
                    unused, data["associated_after"] = discover(clients[host], arguments.mac)
                except Exception:
                    data["verification_error"] = True
            json.dump(report, output, indent=2)
            output.write("\n")
    success = report["completed"] and all(data.get("configuration_unchanged") and data.get("ruleset_restored")
                                          for data in report["ap"].values())
    print(json.dumps({"success": success, "report": str(destination), "error": report.get("error")}))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
