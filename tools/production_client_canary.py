#!/usr/bin/env python3
"""Bounded production-code ARP and LTE canary for one Windows LAN client."""

import argparse
import configparser
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time
import uuid

import paramiko

from openwrt_ap_audit import private_directory
from windows_client_acceptance import connect, powershell


def remote(client, command, timeout=30, optional=False):
    stdin, stdout, stderr = client.exec_command("sudo -n sh -c " + shlex.quote(command), timeout=timeout)
    stdin.close()
    output, errors = stdout.read(65537).decode(), stderr.read(8193).decode()
    status = stdout.channel.recv_exit_status()
    if len(output) > 65536 or len(errors) > 8192:
        raise RuntimeError("VM canary response exceeded its limit")
    if status and not optional:
        raise RuntimeError("VM canary command failed: " + errors.strip())
    return output.strip(), status


def windows_action(client, guard, directory, action, extra=""):
    return json.loads(powershell(client, f"& '{guard}' -Action {action} -RunDirectory '{directory}' {extra}"))


def windows_ipv4(client):
    output = powershell(client, "$trace = & curl.exe -4 -sS --max-time 8 https://www.cloudflare.com/cdn-cgi/trace; "
                        "if ($LASTEXITCODE -ne 0) { throw 'IPv4 HTTPS probe failed' }; "
                        "$line = $trace | Where-Object { $_ -like 'ip=*' } | Select-Object -First 1; "
                        "if (-not $line) { throw 'IPv4 trace response has no address' }; $line.Substring(3)")
    return output.strip()


def windows_gateway_mac(client, address, interface_index):
    output = powershell(client,
        f"Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {interface_index} -IPAddress '{address}' | "
        "Where-Object State -notin @('Unreachable','Incomplete') | "
        "Select-Object -First 1 LinkLayerAddress,State | ConvertTo-Json -Compress")
    return json.loads(output)["LinkLayerAddress"].replace("-", ":").lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-host", required=True)
    parser.add_argument("--client-user", required=True)
    parser.add_argument("--client-known-hosts", required=True)
    parser.add_argument("--client-mac", required=True)
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--vm-host", required=True)
    parser.add_argument("--vm-key", required=True)
    parser.add_argument("--vm-known-hosts", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--test-process-crash-recovery", action="store_true",
                        help="Kill the canary worker and verify its independent VM timer restores one client")
    arguments = parser.parse_args()
    try:
        target = ipaddress.IPv4Address(arguments.client_ip)
        if target not in ipaddress.IPv4Network("192.168.1.0/24") or target in (
                ipaddress.IPv4Address("192.168.1.0"), ipaddress.IPv4Address("192.168.1.255"),
                ipaddress.IPv4Address("192.168.1.253"), ipaddress.IPv4Address("192.168.1.254")):
            raise ValueError("Use an ordinary household client address")
    except ValueError as error:
        parser.error("Invalid client IPv4 address: " + str(error))
    if (not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", arguments.client_mac.lower())
            or int(arguments.client_mac[:2], 16) & 1):
        parser.error("Use a nonzero unicast client MAC")
    destination = Path(arguments.report)
    if destination.exists() or not destination.parent.is_dir() or not private_directory(destination.parent):
        parser.error("Use a NEW report in an existing private directory")
    identifier = uuid.uuid4().hex[:12]
    run_id = "prod-canary-" + identifier
    vm_directory = "/run/failsafe4g-" + run_id
    runtime = vm_directory + "/runtime"
    config_path = vm_directory + "/canary.conf"
    worker_path = vm_directory + "/production_client_canary_worker.py"
    source_path = vm_directory + "/freebox_ethernet.py"
    unit = "failsafe4g-" + run_id
    windows_directory = "C:\\ProgramData\\failsafe4g-tests\\" + run_id
    bootstrap = "C:\\ProgramData\\failsafe4g-tests\\windows_client_pilot_canary.ps1"
    guard = windows_directory + "\\windows_client_pilot.ps1"
    report = {"scope": "single wired Windows client; synthetic primary outage; real Bouygues LTE; no fibre disconnect",
              "client_ip": arguments.client_ip, "client_mac": arguments.client_mac.lower(),
              "production_ready": False, "observations": []}
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    client, vm = None, None
    armed, worker_pid, timer_started, log = False, None, False, None
    try:
        client = connect(arguments.client_host, arguments.client_user, arguments.client_known_hosts,
                         password=os.environ["FAILSAFE_SSH_PASSWORD"])
        vm = paramiko.SSHClient()
        vm.load_host_keys(arguments.vm_known_hosts)
        vm.set_missing_host_key_policy(paramiko.RejectPolicy())
        vm.connect(arguments.vm_host, username="freebox", key_filename=arguments.vm_key,
                   look_for_keys=False, allow_agent=False, timeout=8, banner_timeout=8, auth_timeout=8)
        baseline = json.loads(powershell(client,
            f"$matches = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '{arguments.client_ip}'); "
            "if ($matches.Count -ne 1) { throw 'Target address must identify one interface' }; "
            "$adapter = Get-NetAdapter -InterfaceIndex $matches[0].InterfaceIndex; "
            "[ordered]@{IPAddress=$matches[0].IPAddress; InterfaceIndex=$matches[0].InterfaceIndex; MacAddress=$adapter.MacAddress} "
            "| ConvertTo-Json -Compress"))
        if (baseline["IPAddress"] != arguments.client_ip or
                baseline["MacAddress"].replace("-", ":").lower() != arguments.client_mac.lower()):
            raise RuntimeError("The selected Windows address did not match the target")
        report["primary_ipv4_before"] = windows_ipv4(client)
        report["primary_gateway_mac_before"] = windows_gateway_mac(
            client, "192.168.1.254", baseline["InterfaceIndex"])
        with vm.open_sftp() as transfer:
            config_output, unused = remote(vm, "cat /etc/freebox_ethernet.conf")
            configuration = configparser.ConfigParser(interpolation=None)
            configuration.read_string(config_output)
            section = configuration["ethernet"]
            report["prior_installed_mode"] = {"enabled": section.get("enabled", "false"),
                                               "backup_gateway": section.get("backup_gateway", "")}
            section["enabled"] = "true"
            section["backup_gateway"] = "192.168.1.253"
            section["dns"] = "192.168.1.253"
            section["ipv6_policy"] = "best_effort"
            section["accept_ipv6_limitations"] = "true"
            section["lan_ipv6_disabled"] = "false"
            section["check"] = "1"
            section["down"] = "5"
            section["up"] = "2"
            section["garp"] = "2"
            section["standby_check"] = "2"
            section["health_rise"] = "2"
            section["health_fall"] = "2"
            section["probe_timeout"] = "1"
            configuration_path = Path(tempfile.gettempdir()) / (run_id + ".conf")
            with configuration_path.open("w", encoding="utf-8") as output:
                configuration.write(output)
            transfer.put(str(Path(__file__).with_name("production_client_canary_worker.py")),
                         "/tmp/" + run_id + "-worker.py")
            transfer.put(str(Path(__file__).resolve().parent.parent / "freebox_ethernet.py"),
                         "/tmp/" + run_id + "-daemon.py")
            transfer.put(str(configuration_path), "/tmp/" + run_id + ".conf")
            configuration_path.unlink()
        remote(vm, f"install -d -m 700 {shlex.quote(vm_directory)} {shlex.quote(runtime)}; "
                    f"install -m 700 /tmp/{run_id}-worker.py {shlex.quote(worker_path)}; "
                    f"install -m 600 /tmp/{run_id}-daemon.py {shlex.quote(source_path)}; "
                    f"install -m 600 /tmp/{run_id}.conf {shlex.quote(config_path)}; "
                    f"rm -f /tmp/{run_id}-worker.py /tmp/{run_id}-daemon.py /tmp/{run_id}.conf")
        with client.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("windows_client_pilot.ps1")), bootstrap)
        windows_action(client, bootstrap, windows_directory, "Snapshot", f"-ClientAddress '{arguments.client_ip}'")
        with client.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name("windows_client_pilot.ps1")), guard)
        windows_action(client, guard, windows_directory, "Arm")
        armed = True
        if not windows_action(client, guard, windows_directory, "TestRollback")["Matched"]:
            raise RuntimeError("Windows SYSTEM rollback canary failed")
        timer_delay = 120 if arguments.test_process_crash_recovery else 105
        timer_command = (f"systemd-run --quiet --unit={unit} --on-active={timer_delay}s "
                         f"--timer-property=AccuracySec=1s /usr/bin/python3 {shlex.quote(worker_path)} "
                         f"--source {shlex.quote(source_path)} --config {shlex.quote(config_path)} "
                         f"--runtime {shlex.quote(runtime)} --client-mac {shlex.quote(arguments.client_mac.lower())} "
                         f"--client-ip {shlex.quote(arguments.client_ip)} --recover")
        remote(vm, timer_command)
        timer_started = True
        log = vm_directory + "/canary.log"
        worker = (f"PYTHONPATH=/opt/freebox-failover timeout --signal=TERM --kill-after=15 120 "
                  f"/usr/bin/python3 {shlex.quote(worker_path)} --source {shlex.quote(source_path)} "
                  f"--config {shlex.quote(config_path)} --runtime {shlex.quote(runtime)} "
                  f"--client-mac {shlex.quote(arguments.client_mac.lower())} --client-ip {shlex.quote(arguments.client_ip)}")
        if arguments.test_process_crash_recovery:
            worker += " --lease-seconds 90"
        output, unused = remote(vm, f"setsid sh -c {shlex.quote(worker + ' >' + shlex.quote(log) + ' 2>&1')} "
                                    "</dev/null >/dev/null 2>&1 & echo $!")
        worker_pid = int(output)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            current, status = remote(vm, f"cat {shlex.quote(runtime + '/status.json')}", optional=True)
            if status == 0 and json.loads(current).get("active"):
                break
            time.sleep(1)
        else:
            raise RuntimeError("Production decision did not activate the healthy cellular path")
        report["takeover_seconds_after_launch"] = round(35 - max(0, deadline - time.monotonic()), 1)
        report["gateway_mac_during"] = windows_gateway_mac(
            client, "192.168.1.254", baseline["InterfaceIndex"])
        report["cellular_ipv4_during"] = windows_ipv4(client)
        if report["cellular_ipv4_during"] == report["primary_ipv4_before"]:
            raise RuntimeError("Selected client did not observe a changed public IPv4 address")
        time.sleep(30)
        report["cellular_ipv4_repeat"] = windows_ipv4(client)
        if arguments.test_process_crash_recovery:
            unused, killed_status = remote(
                vm, f"pkill -KILL -f '[p]roduction_client_canary_worker.py.*{run_id}'", optional=True)
            if killed_status != 0:
                raise RuntimeError("Could not SIGKILL the selected canary worker for rollback testing")
            worker_pid = None
            recovery_deadline = time.monotonic() + 90
            while time.monotonic() < recovery_deadline:
                unused, status = remote(vm, f"test ! -e {shlex.quote(runtime + '/network.json')}", optional=True)
                if status == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Independent VM timer did not restore canary network state")
            timer_result, unused = remote(vm, f"systemctl show {unit}.service -p Result --value")
            report["vm_timer_result"] = timer_result
            if timer_result != "success":
                raise RuntimeError("Independent VM rollback service did not complete successfully")
        else:
            state_path = vm_directory + "/wan-state.json"
            remote(vm, f"printf '%s' '{{\"state\":\"up\"}}' > {shlex.quote(state_path)}")
            recovery_deadline = time.monotonic() + 30
            while time.monotonic() < recovery_deadline:
                current, status = remote(vm, f"cat {shlex.quote(runtime + '/status.json')}", optional=True)
                if status == 0 and not json.loads(current).get("active"):
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Production decision did not restore the selected client's primary path")
        report["primary_ipv4_after"] = windows_ipv4(client)
        report["primary_gateway_mac_after"] = windows_gateway_mac(
            client, "192.168.1.254", baseline["InterfaceIndex"])
        if report["primary_ipv4_after"] != report["primary_ipv4_before"]:
            raise RuntimeError("Selected client did not recover its original fibre IPv4 egress")
        if report["primary_gateway_mac_after"] != report["primary_gateway_mac_before"]:
            raise RuntimeError("Selected client did not recover the Freebox gateway ARP entry")
        report["completed"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["cleanup_traceback"] = __import__("traceback").format_exc()
    finally:
        if worker_pid:
            try:
                remote(vm, f"kill -TERM -- -{worker_pid} 2>/dev/null || true; "
                            f"for attempt in 1 2 3 4 5 6 7 8 9 10; do "
                            f"kill -0 -- -{worker_pid} 2>/dev/null || break; sleep 1; done", optional=True)
            except Exception:
                pass
        if vm and vm.get_transport() and vm.get_transport().is_active():
            try:
                if log:
                    log_output, unused = remote(vm, f"cat {shlex.quote(log)}", optional=True)
                    report["daemon_log"] = log_output.splitlines()
                remote(vm, f"printf '%s' '{{\"state\":\"up\"}}' > {shlex.quote(vm_directory + '/wan-state.json')}",
                       optional=True)
                if timer_started:
                    remote(vm, f"systemctl stop {unit}.timer", optional=True)
                remote(vm, f"PYTHONPATH=/opt/freebox-failover /usr/bin/python3 {shlex.quote(worker_path)} "
                            f"--source {shlex.quote(source_path)} --config {shlex.quote(config_path)} "
                            f"--runtime {shlex.quote(runtime)} --client-mac {shlex.quote(arguments.client_mac.lower())} "
                            f"--client-ip {shlex.quote(arguments.client_ip)} --recover", optional=True)
                report["vm_network_clean"] = remote(vm,
                    "test ! -e /run/failsafe4g-" + run_id + "/runtime/network.json && "
                    "! nft list table ip freebox_ethernet >/dev/null 2>&1 && "
                    "[ -z \"$(ip -4 rule show | sed -n '/10424/p')\" ] && "
                    "[ -z \"$(ip -4 route show table 4242)\" ]", optional=True)[1] == 0
                if report["vm_network_clean"]:
                    remote(vm, f"rm -rf -- {shlex.quote(vm_directory)}")
                    report["vm_temp_clean"] = remote(vm, f"test ! -e {shlex.quote(vm_directory)}", optional=True)[1] == 0
            except Exception as error:
                report["vm_cleanup_error"] = type(error).__name__ + ": " + str(error)
        if armed and client:
            try:
                report["windows_restoration"] = windows_action(client, guard, windows_directory, "Restore")
                if report["windows_restoration"]["Matched"]:
                    windows_action(client, guard, windows_directory, "Disarm")
            except Exception as error:
                report["windows_cleanup_error"] = type(error).__name__ + ": " + str(error)
        report["report_written"] = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        if client:
            client.close()
        if vm:
            vm.close()
    success = (report.get("completed") and report.get("vm_network_clean")
               and report.get("windows_restoration", {}).get("Matched"))
    print(json.dumps({"passed": success, "report": str(destination), "error": report.get("error"),
                      "production_ready": False}, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
