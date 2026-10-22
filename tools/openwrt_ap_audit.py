#!/usr/bin/env python3
"""Read-only OpenWrt AP audit with private configuration backups and pinned SSH."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

import paramiko


CONFIGURATIONS = ("network", "wireless", "dhcp", "firewall", "usteer", "dawn",
                  "system", "dropbear", "uhttpd", "rpcd")


def private_directory(path):
    if os.name != "nt":
        return path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o077
    code = """
$ErrorActionPreference='Stop'
$acl=Get-Acl -LiteralPath $env:FAILSAFE_AUDIT_DIRECTORY
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$unexpected=@($acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed
})
if ($owner -notin $allowed -or $unexpected.Count -ne 0) { exit 1 }
"""
    environment = dict(os.environ, FAILSAFE_AUDIT_DIRECTORY=str(path.resolve()))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
                            env=environment, capture_output=True, timeout=15)
    return result.returncode == 0


def query(client, command, optional=False):
    stdin, stdout, stderr = client.exec_command(command, timeout=15)
    stdin.close()
    output = stdout.read(262145)
    stderr.read(4096)
    if len(output) > 262144:
        raise RuntimeError("Audit response exceeds its bound")
    if stdout.channel.recv_exit_status():
        if optional:
            return None
        raise RuntimeError("Read-only AP query failed")
    return output.decode("utf-8")


def files(client):
    return {name: query(client, "cat " + shlex.quote("/etc/config/" + name),
                        optional=name not in ("network", "wireless", "dhcp"))
            for name in CONFIGURATIONS}


def summarize(report):
    wireless = report["uci"]["wireless"]["values"]
    network = report["uci"]["network"]["values"]
    dhcp = report["uci"]["dhcp"]["values"]
    interfaces = [section for section in wireless.values() if section.get(".type") == "wifi-iface"]
    return {
        "model": report["board"].get("model"),
        "release": report["board"].get("release", {}).get("version"),
        "configuration_unchanged": report["configuration_unchanged"],
        "pending_changes": bool(report["pending_changes_before"]),
        "wireless_interfaces": len(interfaces),
        "ap_interfaces": sum(section.get("mode") == "ap" for section in interfaces),
        "fast_transition_interfaces": sum(str(section.get("ieee80211r", "0")) == "1" for section in interfaces),
        "wireless_uplinks": sum(section.get("mode") in ("sta", "mesh") for section in interfaces),
        "bridge_vlan_sections": sum(section.get(".type") == "bridge-vlan" for section in network.values()),
        "services_running": {name: any(instance.get("running") is True
                                       for instance in data.get(name, {}).get("instances", {}).values())
                             for name, data in report["services"].items()},
        "dhcp_sections": [{"interface": section.get("interface"), "ignore": section.get("ignore"),
                           "ra": section.get("ra"), "dhcpv6": section.get("dhcpv6")}
                          for section in dhcp.values() if section.get(".type") == "dhcp"],
    }


def collect(client):
    report = {"observed_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "read-only AP configuration; not a complete firmware/system backup"}
    report["board"] = json.loads(query(client, "ubus call system board"))
    report["configuration_files"] = files(client)
    report["pending_changes_before"] = query(client, "uci changes")
    report["uci"] = {name: json.loads(query(client, "ubus call uci get " + shlex.quote(json.dumps({"config": name}))))
                     for name in ("network", "wireless", "dhcp")}
    report["lan_status"] = json.loads(query(client, "ubus call network.interface.lan status"))
    report["wireless_status"] = json.loads(query(client, "ubus call network.wireless status"))
    report["device_status"] = json.loads(query(client, "ubus call network.device status"))
    report["services"] = {name: json.loads(query(client, "ubus call service list " + shlex.quote(json.dumps({"name": name}))))
                          for name in ("odhcpd", "dnsmasq", "usteer", "dawn")}
    report["links"] = query(client, "ip link show")
    report["bridge_vlans"] = query(client, "bridge vlan show", optional=True)
    report["configuration_hashes"] = {
        name: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for name, value in report["configuration_files"].items() if value is not None}
    report["pending_changes_after"] = query(client, "uci changes")
    report["configuration_unchanged"] = (
        files(client) == report["configuration_files"]
        and report["pending_changes_before"] == report["pending_changes_after"])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--output", required=True, help="NEW secret-bearing JSON file in an existing private directory")
    arguments = parser.parse_args()
    destination = Path(arguments.output)
    if not destination.parent.is_dir() or destination.exists():
        parser.error("Use a new filename in an existing private directory")
    if not private_directory(destination.parent):
        parser.error("Report directory must be private to the current user, administrators and SYSTEM")
    with paramiko.SSHClient() as client:
        client.load_host_keys(arguments.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(arguments.host, username=arguments.user, password=os.environ["FAILSAFE_AP_PASSWORD"],
                       allow_agent=False, look_for_keys=False, timeout=8, banner_timeout=8, auth_timeout=8)
        report = collect(client)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps(summarize(report), indent=2))
    return 0 if report["configuration_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
