#!/usr/bin/env python3
"""Bounded phone-only LTE steering, DNS redirection and public IPv6 loss."""

import argparse
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
import traceback
import uuid

import paramiko

from android_ipv4_fallback import configuration_hash, discover, query
from openwrt_ap_audit import private_directory


def dns_probe(server, transport):
    identifier = secrets.randbelow(65536)
    question = b"\x03www\x0acloudflare\x03com\x00\x00\x01\x00\x01"
    packet = struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0) + question
    kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as connection:
        connection.settimeout(3)
        connection.connect((str(server), 53))
        if transport == "tcp":
            connection.sendall(struct.pack("!H", len(packet)) + packet)

            def receive(length):
                result = b""
                while len(result) < length:
                    chunk = connection.recv(length - len(result))
                    if not chunk:
                        raise RuntimeError("Truncated DNS TCP response")
                    result += chunk
                return result

            length = struct.unpack("!H", receive(2))[0]
            if not 12 <= length <= 4096:
                raise RuntimeError("DNS TCP response length out of bounds")
            response = receive(length)
        else:
            connection.send(packet)
            response = connection.recv(4096)
    if len(response) < 12:
        raise RuntimeError("Truncated DNS response")
    returned_id, flags, questions, answers, unused, unused = struct.unpack("!6H", response[:12])
    if returned_id != identifier or not flags & 0x8000 or flags & 0x020f or questions != 1 or not answers:
        raise RuntimeError(f"{transport.upper()} DNS did not return a usable answer (rcode {flags & 15})")
    if response[12:12 + len(question)] != question:
        raise RuntimeError("Unexpected DNS question in response")
    return {"transport": transport, "rcode": flags & 15, "answers": answers}


def backup_health(client, server, initial_uptime=None):
    output, unused = query(client, "ubus call network.interface.wan status")
    status = json.loads(output)
    if not status.get("up") or status.get("l3_device") != "wwan0":
        raise RuntimeError("Cellular WAN is not up; phone steering must stop")
    if initial_uptime is not None and status.get("uptime", 0) < initial_uptime:
        raise RuntimeError("Cellular session restarted during the experiment")
    dns = [dns_probe(server, transport) for transport in ("udp", "tcp")]
    trace, unused = query(client, "uclient-fetch -4 -T 8 -O - https://www.cloudflare.com/cdn-cgi/trace")
    fields = dict(line.split("=", 1) for line in trace.splitlines() if "=" in line)
    address = ipaddress.IPv4Address(fields.get("ip", ""))
    if not address.is_global:
        raise RuntimeError("LTE HTTPS probe did not report a public IPv4 address")
    return {"uptime": status.get("uptime"), "dns": dns, "https_public_ip": str(address)}


def device_hash(client, family):
    if family == "netdev":
        return configuration_hash(client)
    output, unused = query(client, "sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall")
    return hashlib.sha256(output.encode()).hexdigest()


def mac_address(value):
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value) or int(value[:2], 16) & 1 or value == "00:00:00:00:00:00":
        raise argparse.ArgumentTypeError("Use a lowercase nonzero unicast MAC")
    return value


def ap_rules(table, interfaces, mac, address, network, primary_mac, router_mac):
    lines = [f"table netdev {table} {{"]
    match = f"ether saddr {mac} ether daddr {primary_mac} ip saddr {address}"
    for index, interface in enumerate(interfaces):
        lines.extend([
            f" chain wifi{index} {{",
            f'  type filter hook ingress device "{interface}" priority -500; policy accept;',
            f"  ether saddr {mac} ether type ip6 ip6 daddr 2000::/3 counter drop;",
            f"  ether saddr {mac} ether type ip6 meta l4proto {{ tcp, udp }} th dport 53 counter drop;",
            f"  {match} meta l4proto {{ tcp, udp }} th dport 53 counter ether daddr set {router_mac};",
            f"  {match} ip daddr != {network} counter ether daddr set {router_mac};",
            " }",
        ])
    return "\n".join(lines + ["}", ""])


def router_rules(table, mac, address, router_ip):
    return f"""table inet {table} {{
 chain dns {{
  type nat hook prerouting priority -101; policy accept;
  iifname "br-lan" ether saddr {mac} ip saddr {address} meta l4proto {{ tcp, udp }} th dport 53 counter dnat ip to {router_ip};
 }}
 chain traffic {{
  type filter hook forward priority -1; policy accept;
  iifname "br-lan" oifname "wwan0" ether saddr {mac} ip saddr {address} counter;
  iifname "wwan0" oifname "br-lan" ip daddr {address} counter;
 }}
}}
"""


def arm(client, family, table, rules, seconds):
    directory = "/tmp/" + table
    guard = ("trap '' HUP\n"
             f"trap 'nft delete table {family} {table} 2>/dev/null' EXIT\n"
             f"nft -f {directory}/rules.nft || exit 1\n"
             f"date +%s > {directory}/ready\n"
             f"sleep {seconds}\n"
             f"nft delete table {family} {table} || exit 1\n"
             f"date +%s > {directory}/expired\n")
    query(client, f"umask 077; mkdir {directory}; cat > {directory}/guard.sh", guard)
    query(client, f"umask 077; cat > {directory}/rules.nft", rules)
    query(client, f"setsid sh {directory}/guard.sh </dev/null >{directory}/guard.log 2>&1 &\n"
          f"for attempt in 1 2 3 4 5; do test -f {directory}/ready && exit 0; sleep 1; done; exit 1")


def counters(client, family, table):
    listing, status = query(client, f"nft -j list table {family} {table}", optional=True)
    if status:
        return None
    entries = [entry["rule"] for entry in json.loads(listing)["nftables"] if "rule" in entry]
    return [{"chain": entry["chain"], "handle": entry["handle"],
             "counter": next((expression["counter"] for expression in entry["expr"] if "counter" in expression), {})}
            for entry in entries]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ap", action="append", required=True)
    parser.add_argument("--ap-known-hosts", required=True)
    parser.add_argument("--router", required=True, type=ipaddress.IPv4Address)
    parser.add_argument("--router-known-hosts", required=True)
    parser.add_argument("--router-key", required=True)
    parser.add_argument("--router-mac", required=True, type=mac_address)
    parser.add_argument("--primary-mac", required=True, type=mac_address)
    parser.add_argument("--mac", required=True, type=mac_address)
    parser.add_argument("--address", required=True, type=ipaddress.IPv4Address)
    parser.add_argument("--network", required=True, type=ipaddress.IPv4Network)
    parser.add_argument("--report", required=True)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--stability-seconds", type=int, default=180)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--confirm-cellular-off", action="store_true")
    parser.add_argument("--automatic", action="store_true", help="Rehearse namespace-driven phone-only takeover/recovery")
    parser.add_argument("--vm-host")
    parser.add_argument("--vm-key")
    parser.add_argument("--vm-known-hosts")
    parser.add_argument("--vm-uplink", default="192.168.1.251/24")
    arguments = parser.parse_args()
    if not 30 <= arguments.seconds <= 180 or arguments.address not in arguments.network or arguments.router not in arguments.network:
        parser.error("Use LAN addresses and a duration of 30..180 seconds")
    if not 180 <= arguments.stability_seconds <= 300:
        parser.error("Require 180..300 seconds of healthy backup before steering")
    if arguments.address == arguments.router or len(set(arguments.ap)) != len(arguments.ap):
        parser.error("Client/router must differ and APs must be unique")
    if len({arguments.mac, arguments.primary_mac, arguments.router_mac}) != 3:
        parser.error("Client, primary and backup MACs must differ")
    if arguments.run and not arguments.confirm_cellular_off:
        parser.error("Confirm phone cellular data is off")
    if arguments.automatic and (arguments.seconds != 180 or not all(
            (arguments.vm_host, arguments.vm_key, arguments.vm_known_hosts))):
        parser.error("Automatic rehearsal requires --seconds 180 and pinned VM SSH arguments")
    if arguments.automatic:
        from android_automatic_pilot import AutomaticPhonePilot, ap_rules as automatic_ap_rules
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW report in an existing private directory")
    table = "f4g_phone_" + uuid.uuid4().hex[:12]
    report = {"scope": "selected phone only; public IPv4 and DNS via LTE, public IPv6 and IPv6 DNS dropped",
              "target_mac": arguments.mac, "target_ip": str(arguments.address), "devices": {}, "completed": False,
              "application_acceptance": "not established; requires user observations", "backup_health": [],
              "required_stability_seconds": arguments.stability_seconds, "stability_gate_passed": False}
    if arguments.automatic:
        report["scope"] = "phone-only synthetic outage; namespace health decisions trigger real LTE steering and native fibre recovery"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output, ExitStack() as stack:
        devices, armed, automatic = {}, [], None
        try:
            for host, family in [(str(arguments.router), "inet")] + [(host, "netdev") for host in arguments.ap]:
                if host in devices:
                    raise ValueError("AP and router must differ")
                client = stack.enter_context(paramiko.SSHClient())
                client.load_host_keys(arguments.router_known_hosts if family == "inet" else arguments.ap_known_hosts)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                credentials = {"key_filename": arguments.router_key} if family == "inet" else {"password": os.environ["FAILSAFE_AP_PASSWORD"]}
                client.connect(host, username="root", look_for_keys=False, allow_agent=False,
                               timeout=8, banner_timeout=8, auth_timeout=8, **credentials)
                baseline, unused = query(client, "nft -s list ruleset")
                if "f4g_phone_" in baseline:
                    raise RuntimeError("An existing phone test is present")
                query(client, "command -v setsid >/dev/null")
                data = {"family": family, "configuration_before": device_hash(client, family), "ruleset_before": baseline}
                report["devices"][host] = data
                devices[host] = client
                if family == "inet":
                    address, unused = query(client, "cat /sys/class/net/br-lan/address")
                    if address.strip() != arguments.router_mac:
                        raise RuntimeError("Backup router MAC mismatch")
                    status, unused = query(client, "ubus call network.interface.wan status")
                    status = json.loads(status)
                    if not status.get("up") or status.get("l3_device") != "wwan0":
                        raise RuntimeError("LTE is not up on the expected interface")
                    routes, unused = query(client, "ip -4 route show default")
                    if "dev wwan0" not in routes or len(routes.strip().splitlines()) != 1:
                        raise RuntimeError("Backup does not have an exclusively cellular default route")
                    data["wan_before"] = status
                    rules = router_rules(table, arguments.mac, arguments.address, arguments.router)
                else:
                    interfaces, associated = discover(client, arguments.mac)
                    data["associated_before"] = associated
                    build_rules = automatic_ap_rules if arguments.automatic else ap_rules
                    rules = build_rules(table, interfaces, arguments.mac, arguments.address, arguments.network,
                                        arguments.primary_mac, arguments.router_mac)
                query(client, "nft -c -f -", rules)
                data["rules"] = rules
            if not any(data.get("associated_before") for data in report["devices"].values()):
                raise RuntimeError("Phone is not associated")
            if arguments.run:
                router = devices[str(arguments.router)]
                health = backup_health(router, arguments.router)
                report["backup_health"].append(health)
                previous_uptime = health["uptime"]
                stable_until = time.monotonic() + arguments.stability_seconds
                print(json.dumps({"phase": "qualifying backup", "phone_steering_enabled": False,
                                  "required_seconds": arguments.stability_seconds}), flush=True)
                while time.monotonic() < stable_until:
                    time.sleep(min(10, max(0, stable_until - time.monotonic())))
                    health = backup_health(router, arguments.router, previous_uptime)
                    report["backup_health"].append(health)
                    previous_uptime = health["uptime"]
                    print(json.dumps({"phase": "qualifying backup", "phone_steering_enabled": False,
                                      "remaining_seconds": max(0, round(stable_until - time.monotonic()))}), flush=True)
                report["stability_gate_passed"] = True
                if not any(discover(devices[host], arguments.mac)[1] for host in arguments.ap):
                    raise RuntimeError("Phone is no longer associated after backup qualification")
                canary = table + "_canary"
                arm(router, "inet", canary, f"table inet {canary} {{\n}}\n", 5)
                time.sleep(6)
                unused, present = query(router, f"nft list table inet {canary}", optional=True)
                unused, expired = query(router, f"test -f /tmp/{canary}/expired", optional=True)
                if present == 0 or expired:
                    raise RuntimeError("Router independent rollback canary failed")
                report["router_rollback_canary_passed"] = True
                if arguments.automatic:
                    automatic = AutomaticPhonePilot(arguments, report)
                    automatic.start()
                for host, client in devices.items():
                    data = report["devices"][host]
                    armed.append(host)
                    arm(client, data["family"], table, data["rules"], arguments.seconds + (30 if data["family"] == "inet" else 0))
                print(json.dumps({"active": not arguments.automatic, "automatic_rehearsal_armed": arguments.automatic,
                                  "seconds": arguments.seconds, "scope": report["scope"]}), flush=True)
                deadline = time.monotonic() + arguments.seconds + 32
                if automatic:
                    automatic.exercise(devices, table)
                next_health = time.monotonic()
                while time.monotonic() < deadline:
                    time.sleep(min(5, max(0, deadline - time.monotonic())))
                    if time.monotonic() >= next_health:
                        health = backup_health(router, arguments.router, previous_uptime)
                        report["backup_health"].append(health)
                        previous_uptime = health["uptime"]
                        next_health = time.monotonic() + 10
                    snapshot = {}
                    for host, client in devices.items():
                        observed = counters(client, report["devices"][host]["family"], table)
                        if observed is not None:
                            report["devices"][host]["last_counters"] = observed
                            snapshot[host] = observed
                    print(json.dumps({"counters": snapshot}), flush=True)
                for host, client in devices.items():
                    data = report["devices"][host]
                    unused, expired = query(client, f"test -f /tmp/{table}/expired", optional=True)
                    data["independent_expiry_verified"] = expired == 0 and counters(client, data["family"], table) is None
                    if not data["independent_expiry_verified"]:
                        raise RuntimeError("Independent expiry not verified")
            report["completed"] = True
        except (Exception, KeyboardInterrupt) as error:
            report["error"] = type(error).__name__ + ": " + str(error)
            report["error_traceback"] = traceback.format_exc()
        finally:
            for host in reversed(armed):
                try:
                    query(devices[host], f"nft delete table {report['devices'][host]['family']} {table}", optional=True)
                except Exception:
                    report["devices"][host]["cleanup_error"] = True
            if automatic:
                try:
                    automatic.close()
                except Exception as error:
                    report["completed"] = False
                    report["vm_cleanup_error"] = str(error)
            for host, data in report["devices"].items():
                try:
                    data["configuration_unchanged"] = device_hash(devices[host], data["family"]) == data["configuration_before"]
                    current, unused = query(devices[host], "nft -s list ruleset")
                    data["ruleset_restored"] = current == data["ruleset_before"]
                except Exception:
                    data["verification_error"] = True
            json.dump(report, output, indent=2)
            output.write("\n")
    success = report["completed"] and all(data.get("configuration_unchanged") and data.get("ruleset_restored")
                                          for data in report["devices"].values())
    print(json.dumps({"control_and_cleanup_ok": success, "application_acceptance": report["application_acceptance"],
                      "error": report.get("error"), "report": str(destination)}))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
