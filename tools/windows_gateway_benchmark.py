#!/usr/bin/env python3
"""Measure one Windows client's local namespace NAT path with automatic rollback."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shlex
import time

import paramiko

from gateway_benchmark import PORT, SIZE, TARGET
from openwrt_ap_audit import private_directory
from windows_client_acceptance import connect, powershell


def traffic_evidence(state):
    forwarded = [expression["counter"]["bytes"]
                 for entry in state["forwarding_counters"]["nftables"]
                 for expression in entry.get("rule", {}).get("expr", []) if "counter" in expression]
    flows = sum(expression["counter"]["packets"] for entry in state["nat_counters"]["nftables"]
                for expression in entry.get("rule", {}).get("expr", []) if "counter" in expression)
    passed = len(forwarded) == 2 and all(size >= 2 * SIZE for size in forwarded) and flows >= 4
    return {"forwarded_bytes": forwarded, "nat_first_packets": flows, "passed": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "user", "known-hosts", "vm-host", "vm-key", "vm-known-hosts", "uplink-address", "report"):
        parser.add_argument("--" + name, required=True)
    arguments = parser.parse_args()
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW report file in an existing private directory")
    run_id = "pilot-" + time.strftime("%Y%m%d%H%M%S", time.gmtime())
    directory = "C:\\ProgramData\\failsafe4g-tests\\" + run_id
    guard = directory + "\\windows_client_pilot.ps1"
    payload = directory + "\\benchmark.bin"
    control = "/run/failsafe4g-benchmark-" + run_id
    script = "/tmp/failsafe4g-benchmark-" + run_id + ".py"
    log = "/var/log/failsafe4g-pilot/benchmark-" + run_id + ".log"
    report = {"production_ready": False, "samples": [], "scope": "local selected-client IPv4 forwarding/SNAT, no WAN or LTE traffic"}
    windows = connect(arguments.host, arguments.user, arguments.known_hosts, password=os.environ["FAILSAFE_SSH_PASSWORD"])
    virtual = connect(arguments.vm_host, "freebox", arguments.vm_known_hosts,
                      pkey=paramiko.Ed25519Key.from_private_key_file(arguments.vm_key))
    armed, started = False, False

    def root(code):
        stdin, stdout, stderr = virtual.exec_command("sudo -n sh -c " + shlex.quote(code), timeout=30)
        stdin.close()
        output, errors = stdout.read().decode(), stderr.read().decode()
        if stdout.channel.recv_exit_status():
            raise RuntimeError("VM benchmark control failed")
        return output.strip()

    def action(name, extra=""):
        return json.loads(powershell(windows, f"& '{guard}' -Action {name} -RunDirectory '{directory}' {extra}"))

    try:
        temporary = powershell(windows, "$env:TEMP").replace("\\", "/") + "/" + run_id + ".ps1"
        with windows.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("windows_client_pilot.ps1")), temporary)
        powershell(windows, f"& '{temporary}' -Action Snapshot -RunDirectory '{directory}' -ClientAddress '{arguments.host}'; Copy-Item -LiteralPath '{temporary}' -Destination '{guard}'; Remove-Item -LiteralPath '{temporary}'")
        action("Arm")
        armed = True
        if not action("TestRollback")["Matched"]:
            raise RuntimeError("Local SYSTEM rollback canary did not pass")
        baseline = json.loads(powershell(windows, f"Get-Content -LiteralPath '{directory}\\baseline.json' -Raw"))
        interface = baseline["Configuration"]["InterfaceIndex"]
        adapter = json.loads(powershell(windows, f"Get-NetAdapter | Where-Object ifIndex -eq {interface} | Select-Object MacAddress,LinkSpeed | ConvertTo-Json -Compress"))
        report["client_link_speed"] = adapter["LinkSpeed"]
        candidate = str(ipaddress.IPv4Interface(arguments.uplink_address).ip)
        report["neighbor_before"] = json.loads(powershell(windows, f"@(Get-NetNeighbor -InterfaceIndex {interface} -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{candidate}' | Select-Object LinkLayerAddress,State) | ConvertTo-Json -Compress") or "null")
        with virtual.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("gateway_benchmark.py")), script)
        launch = ["python3", script, "--run", "--control", control, "--client", arguments.host,
                  "--mac", adapter["MacAddress"].replace("-", ":").lower(), "--uplink-address", arguments.uplink_address]
        root("install -d -m 700 /var/log/failsafe4g-pilot; umask 077; nohup timeout --signal=TERM --kill-after=15 150 " +
             " ".join(shlex.quote(value) for value in launch) + f" > {log} 2>&1 < /dev/null & echo $!")
        started = True
        state = None
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            state = json.loads(root(f"if [ -f {control}/state.json ]; then cat {control}/state.json; else echo null; fi"))
            if state and state.get("ready"):
                break
            if state and "host_network_restored" in state:
                raise RuntimeError("Benchmark setup failed; inspect its private VM log")
            time.sleep(0.5)
        else:
            raise RuntimeError("Local benchmark namespace did not become ready")
        action("Arm")
        report["route_application"] = action("ApplyBenchmark", f"-Gateway '{state['gateway']}'")
        neighbor = json.loads(powershell(windows, f"Get-NetNeighbor -InterfaceIndex {interface} -IPAddress '{state['gateway']}' | Select-Object LinkLayerAddress,State | ConvertTo-Json -Compress"))
        if neighbor["LinkLayerAddress"].replace("-", ":").lower() != state["gateway_mac"]:
            raise RuntimeError("Client neighbor cache did not learn the explicit pilot identity")
        report["neighbor_after"] = neighbor
        powershell(windows, f"$stream=[IO.File]::Open('{payload}',[IO.FileMode]::CreateNew); try {{ $stream.SetLength({SIZE}) }} finally {{ $stream.Dispose() }}")
        print("Benchmark route is limited to one test address; normal defaults and DNS unchanged", flush=True)
        for direction in ("download", "upload"):
            for sample in range(2):
                transfer_arguments = "" if direction == "download" else f"--header 'Expect:' --upload-file '{payload}'"
                metric = "download" if direction == "download" else "upload"
                url = f"http://{TARGET}:{PORT}/{state['token']}/{direction}"
                output = powershell(windows, f"$result=& curl.exe --noproxy '*' --fail --silent --show-error --connect-timeout 3 --max-time 20 {transfer_arguments} --output NUL --write-out '%{{size_{metric}}} %{{speed_{metric}}} %{{time_total}}' '{url}'; if ($LASTEXITCODE -ne 0) {{ throw 'Local benchmark transfer failed' }}; $result")
                size, speed, duration = (float(value) for value in output.split())
                if size != SIZE or speed <= 0 or duration <= 0:
                    raise RuntimeError("Benchmark byte count/timing did not validate")
                result = {"direction": direction, "bytes": int(size), "mbps": round(speed * 8 / 1_000_000, 2), "seconds": duration}
                report["samples"].append(result)
                print(json.dumps(result), flush=True)
                time.sleep(1)
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        try:
            if armed:
                report["restoration"] = action("Restore")
                if not report["restoration"]["Matched"]:
                    raise RuntimeError("Windows restoration mismatch; local task remains armed")
                action("Disarm")
                powershell(windows, f"if (Test-Path -LiteralPath '{payload}') {{ Remove-Item -LiteralPath '{payload}' }}")
        finally:
            try:
                if started:
                    root(f"if [ -d {control} ]; then touch {control}/stop; fi")
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        final = json.loads(root(f"if [ -f {control}/state.json ]; then cat {control}/state.json; else echo null; fi"))
                        if final and final.get("host_network_restored") is True and not final.get("ready"):
                            report["gateway"] = final
                            if len(report["samples"]) == 4:
                                report["traffic_evidence"] = traffic_evidence(final)
                                if not report["traffic_evidence"]["passed"] or not final.get("no_internet_default"):
                                    raise RuntimeError("NAT/forwarding confinement evidence did not validate")
                            break
                        time.sleep(0.5)
                    else:
                        raise RuntimeError("Namespace cleanup not confirmed; inspect private log")
            finally:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                    json.dump(report, output, indent=2)
                windows.close()
                virtual.close()
    print(json.dumps({"windows_restored": report["restoration"]["Matched"],
                      "host_network_restored": report["gateway"]["host_network_restored"],
                      "nat_forwarding_validated": report["traffic_evidence"]["passed"],
                      "no_internet_default": report["gateway"]["no_internet_default"],
                      "production_ready": False}, indent=2))


if __name__ == "__main__":
    main()
