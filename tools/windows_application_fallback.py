#!/usr/bin/env python3
"""Observe Windows application fallback under selected-client IPv6 silent loss."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
from pathlib import Path
import shlex
import time

import paramiko

from openwrt_ap_audit import private_directory
from windows_client_acceptance import connect, powershell


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "user", "known-hosts", "vm-host", "vm-key", "vm-known-hosts", "uplink-address", "report"):
        parser.add_argument("--" + name, required=True)
    arguments = parser.parse_args()
    try:
        uplink = ipaddress.IPv4Interface(arguments.uplink_address)
        if "/" not in arguments.uplink_address or uplink.network.prefixlen > 30 or uplink.ip in (uplink.network.network_address,
                                                               uplink.network.broadcast_address):
            raise ValueError("Use an ordinary host address with its subnet prefix")
    except ValueError as error:
        parser.error("Invalid --uplink-address: " + str(error))
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW private report file")
    run_id = "pilot-" + time.strftime("%Y%m%d%H%M%S", time.gmtime())
    directory = "C:\\ProgramData\\failsafe4g-tests\\" + run_id
    guard = directory + "\\windows_client_pilot.ps1"
    probe = directory + "\\windows_application_probe.ps1"
    control = "/run/failsafe4g-physical-app-" + run_id
    script = "/tmp/failsafe4g-app-" + run_id + ".py"
    log = "/var/log/failsafe4g-pilot/app-" + run_id + ".log"
    report = {"production_ready": False, "observations": [], "limitations": [],
              "scope": "selected Windows application transports with controlled DNS and temporary routes; not household routing/RA control"}
    windows = connect(arguments.host, arguments.user, arguments.known_hosts, password=os.environ["FAILSAFE_SSH_PASSWORD"])
    virtual = connect(arguments.vm_host, "freebox", arguments.vm_known_hosts,
                      pkey=paramiko.Ed25519Key.from_private_key_file(arguments.vm_key))
    armed, started, request_id = False, False, 0

    def root(code):
        stdin, stdout, stderr = virtual.exec_command("sudo -n sh -c " + shlex.quote(code), timeout=30)
        stdin.close()
        output, errors = stdout.read().decode(), stderr.read().decode()
        if stdout.channel.recv_exit_status():
            raise RuntimeError("VM application-test control failed")
        return output.strip()

    def action(name, extra=""):
        return json.loads(powershell(windows, f"& '{guard}' -Action {name} -RunDirectory '{directory}' {extra}"))

    def status():
        return json.loads(root(f"if [ -f {control}/status.json ]; then cat {control}/status.json; else echo null; fi"))

    def wait(phase):
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            current = status()
            if current and current["phase"] == phase and current["acknowledged_id"] == request_id:
                return current
            time.sleep(0.5)
        raise RuntimeError("Pilot phase/command acknowledgement timed out")

    def request(path, enabled, phase):
        nonlocal request_id
        request_id += 1
        payload = base64.b64encode(json.dumps({"id": request_id, "action": "fault", "path": path, "enabled": enabled}).encode()).decode()
        root(f"printf '%s' {payload} | base64 -d > {control}/command.new; mv {control}/command.new {control}/command.json")
        return wait(phase)

    def drops(namespace):
        rules = json.loads(root(f"ip netns exec {namespace} nft -j list chain inet pilot fault_prerouting"))
        return sum(expression["counter"]["packets"] for entry in rules["nftables"]
                   for expression in entry.get("rule", {}).get("expr", []) if "counter" in expression)

    def observe(stage, engine="curl", family="any", timeout=10):
        namespace = status()["namespace"]
        before = drops(namespace)
        metadata = directory + "\\probe-" + str(len(report["observations"])) + ".json"
        snapshots = []
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(powershell, windows, f"& '{probe}' -Engine {engine} -Family {family} -TimeoutSeconds {timeout} -ObservationPath '{metadata}'")
            while not future.done():
                time.sleep(0.7)
                if future.done():
                    break
                observed = json.loads(powershell(windows, f"if (Test-Path -LiteralPath '{metadata}') {{ $identity=Get-Content -LiteralPath '{metadata}' -Raw | ConvertFrom-Json; @(Get-NetTCPConnection -OwningProcess $identity.ProcessId -ErrorAction SilentlyContinue | Where-Object RemotePort -ne 0 | Select-Object RemoteAddress,RemotePort,State) | ConvertTo-Json -Compress }} else {{ 'null' }}") or "null")
                if observed:
                    snapshots.append(observed)
            result = json.loads(future.result())
        result["tcp_observations"] = snapshots
        result.update(stage=stage, dropped_ipv6_packets=drops(namespace) - before)
        report["observations"].append(result)
        print(json.dumps({key: result[key] for key in ("stage", "Engine", "Family", "Success", "Seconds", "dropped_ipv6_packets")}), flush=True)
        return result

    def applications(stage, expected):
        for engine in ("curl", "webrequest", "httpclient"):
            result = observe(stage, engine)
            if not result["Success"] or result["EgressIP"] not in expected:
                report["limitations"].append({"stage": stage, "engine": engine, "seconds": result["Seconds"], "success": result["Success"]})

    try:
        temporary = powershell(windows, "$env:TEMP").replace("\\", "/") + "/" + run_id + ".ps1"
        with windows.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("windows_client_pilot.ps1")), temporary)
        powershell(windows, f"& '{temporary}' -Action Snapshot -RunDirectory '{directory}' -ClientAddress '{arguments.host}'; Copy-Item -LiteralPath '{temporary}' -Destination '{guard}'; Remove-Item -LiteralPath '{temporary}'")
        with windows.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("windows_application_probe.ps1")), probe)
        action("Arm")
        armed = True
        if not action("TestRollback")["Matched"]:
            raise RuntimeError("Local SYSTEM rollback canary failed")
        baseline = json.loads(powershell(windows, f"Get-Content -LiteralPath '{directory}\\baseline.json' -Raw"))
        interface = baseline["Configuration"]["InterfaceIndex"]
        peer = json.loads(powershell(windows, f"Get-NetAdapter | Where-Object ifIndex -eq {interface} | Select-Object MacAddress | ConvertTo-Json -Compress"))
        with virtual.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("dual_stack_pilot.py")), script)
        launch = ["python3", script, "--run", "--automatic", "--external-control", control,
                  "--physical-client", arguments.host, "--physical-mac", peer["MacAddress"].replace("-", ":").lower(),
                  "--uplink-address", arguments.uplink_address]
        root("install -d -m 700 /var/log/failsafe4g-pilot; umask 077; nohup timeout --signal=TERM --kill-after=15 330 " +
             " ".join(shlex.quote(value) for value in launch) + f" > {log} 2>&1 < /dev/null & echo $!")
        started = True
        current = wait("primary")
        action("Arm")
        action("Apply", f"-Gateway '{current['gateway']}' -IPv6Gateway '{current['ipv6_gateway']}'")
        report["dns_families"] = json.loads(powershell(windows, "@([Net.Dns]::GetHostAddresses('www.cloudflare.com') | ForEach-Object { $_.AddressFamily.ToString() }) | ConvertTo-Json -Compress"))
        if not {"InterNetwork", "InterNetworkV6"}.issubset(report["dns_families"]):
            raise RuntimeError("Dual-stack test hostname must resolve in both families")
        primary4, primary6 = observe("baseline", family="ipv4"), observe("baseline", family="ipv6")
        if not primary4["Success"] or not primary6["Success"]:
            raise RuntimeError("Baseline fibre IPv4/IPv6 controls failed")
        if ipaddress.ip_address(primary6["EgressIP"]) in {
                ipaddress.ip_address(address["IPAddress"].split("%")[0]) for address in baseline["Configuration"]["Addresses"]}:
            raise RuntimeError("IPv6 baseline bypassed the pilot")
        applications("baseline", {primary4["EgressIP"], primary6["EgressIP"]})
        request("client_ipv6_blackhole", True, "primary")
        current = request("primary", True, "backup")
        backup4 = observe("silent_drop", family="ipv4")
        forced6 = observe("silent_drop", family="ipv6", timeout=4)
        if not backup4["Success"] or backup4["EgressIP"] == primary4["EgressIP"] or forced6["Success"] or forced6["dropped_ipv6_packets"] < 1:
            raise RuntimeError("Silent IPv6-loss / actual cellular controls did not validate")
        applications("silent_drop", {backup4["EgressIP"]})
        observe("silent_drop_repeat")
        for engine in ("webrequest", "httpclient"):
            extended = observe("silent_drop_extended", engine=engine, timeout=20)
            if not extended["Success"]:
                report["limitations"].append({"stage": "silent_drop_extended", "engine": engine,
                                             "seconds": extended["Seconds"], "success": False})
        request("client_ipv6_blackhole", False, "backup")
        applications("immediate_reject", {backup4["EgressIP"]})
        current = request("primary", False, "primary")
        restored4, restored6 = observe("restored", family="ipv4"), observe("restored", family="ipv6")
        if not restored4["Success"] or not restored6["Success"] or restored4["EgressIP"] != primary4["EgressIP"] or restored6["EgressIP"] != primary6["EgressIP"]:
            raise RuntimeError("Primary family controls did not recover")
        applications("restored", {primary4["EgressIP"], primary6["EgressIP"]})
        report["transitions"] = current["transitions"]
        report["testing_completed"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        try:
            if armed:
                report["restoration"] = action("Restore")
                if not report["restoration"]["Matched"]:
                    raise RuntimeError("Windows restoration mismatch; local guard left armed")
                action("Disarm")
        finally:
            try:
                if started:
                    request_id += 1
                    payload = base64.b64encode(json.dumps({"id": request_id, "action": "stop"}).encode()).decode()
                    root(f"if [ -d {control} ]; then printf '%s' {payload} | base64 -d > {control}/command.new; mv {control}/command.new {control}/command.json; fi")
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if "pilot removed; host routes, rules, firewall and forwarding match baseline" in root("cat " + shlex.quote(log)):
                            report["host_network_restored"] = True
                            break
                        time.sleep(0.5)
                    else:
                        raise RuntimeError("Pilot cleanup not confirmed; inspect private log")
            finally:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(report, output, indent=2)
                windows.close()
                virtual.close()
    print(json.dumps({"testing_completed": True, "limitations": report["limitations"],
                      "windows_restored": report["restoration"]["Matched"],
                      "host_network_restored": report["host_network_restored"], "production_ready": False}, indent=2))


if __name__ == "__main__":
    main()
