#!/usr/bin/env python3
"""Guarded single-Windows-client unicast RA/SLAAC/RDNSS acceptance."""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import shlex
import time

import paramiko

from windows_client_acceptance import connect, powershell


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--known-hosts', required=True)
    parser.add_argument('--vm-host', required=True)
    parser.add_argument('--vm-key', required=True)
    parser.add_argument('--vm-known-hosts', required=True)
    parser.add_argument('--uplink-address', required=True)
    parser.add_argument('--report', required=True)
    arguments = parser.parse_args()
    run_id = 'pilot-' + time.strftime('%Y%m%d%H%M%S', time.gmtime())
    directory = 'C:\\ProgramData\\failsafe4g-tests\\' + run_id
    guard = directory + '\\windows_client_pilot.ps1'
    control = '/run/failsafe4g-physical-ra-' + run_id
    log = '/var/log/failsafe4g-pilot/ra-' + run_id + '.log'
    prefix = 'fd42:4242:72::/64'
    dns_address = str(ipaddress.IPv6Network(prefix).network_address + 1)
    request_id = 0
    started = False
    prepared = False
    task_armed = False
    capture_pid = None
    report = {'passed': [], 'production_ready': False, 'run_directory': directory}
    windows = connect(arguments.host, arguments.user, arguments.known_hosts,
                      password=os.environ['FAILSAFE_SSH_PASSWORD'])
    virtual = connect(arguments.vm_host, 'freebox', arguments.vm_known_hosts,
                      pkey=paramiko.Ed25519Key.from_private_key_file(arguments.vm_key))

    def root(code):
        stdin, stdout, stderr = virtual.exec_command('sudo -n sh -c ' + shlex.quote(code), timeout=60)
        stdin.close()
        output, errors = stdout.read().decode(), stderr.read().decode()
        if stdout.channel.recv_exit_status():
            raise RuntimeError('VM command failed: ' + errors)
        return output.strip()

    def action(name, extra=''):
        return json.loads(powershell(windows, f"& '{guard}' -Action {name} -RunDirectory '{directory}' {extra}"))

    def status():
        return json.loads(root(f'if [ -f {control}/status.json ]; then cat {control}/status.json; else echo null; fi'))

    def send(router_lifetime, dns_lifetime, retire=False, preference=3):
        nonlocal request_id
        request_id += 1
        payload = base64.b64encode(json.dumps({'id': request_id, 'action': 'unicast_ra',
                                               'router_lifetime': router_lifetime, 'dns_lifetime': dns_lifetime,
                                               'retire_prefix': retire, 'preference': preference}).encode()).decode()
        root(f"printf '%s' {payload} | base64 -d > {control}/command.new; mv {control}/command.new {control}/command.json")
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            current = status()
            if current and current['acknowledged_id'] == request_id:
                return current['unicast_ra']
            time.sleep(0.3)
        raise RuntimeError('Unicast probe was not acknowledged')

    def dns_check():
        powershell(windows, f"foreach($tcp in @($false,$true)) {{ $answers=@(Resolve-DnsName www.cloudflare.com -Server '{dns_address}' -Type A -DnsOnly -TcpOnly:$tcp -ErrorAction Stop); if(-not @($answers|Where-Object IPAddress).Count) {{ throw 'Probe IPv6 DNS failed' }} }}; 'DNS_OK'")

    try:
        temporary = powershell(windows, "$env:TEMP").replace('\\', '/') + '/' + run_id + '.ps1'
        with windows.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name('windows_client_pilot.ps1')), temporary)
        powershell(windows, f"& '{temporary}' -Action Snapshot -RunDirectory '{directory}' -ClientAddress '{arguments.host}'; Copy-Item -LiteralPath '{temporary}' -Destination '{guard}'; Remove-Item -LiteralPath '{temporary}'")
        if not action('Verify')['Matched']:
            raise RuntimeError('Initial Windows configuration did not match')
        action('Arm')
        task_armed = True
        if not action('TestRollback')['Matched']:
            raise RuntimeError('SYSTEM rollback canary failed')
        baseline = json.loads(powershell(windows, f"Get-Content -LiteralPath '{directory}\\baseline.json' -Raw"))
        interface = baseline['Configuration']['InterfaceIndex']
        peer = json.loads(powershell(windows, f"$adapter=Get-NetAdapter|Where-Object ifIndex -eq {interface}; $link=@(Get-NetIPAddress -InterfaceIndex {interface} -AddressFamily IPv6|Where-Object IPAddress -like 'fe80::*')[0].IPAddress; @{{MAC=$adapter.MacAddress.Replace('-',':').ToLowerInvariant(); LinkLocal=($link -split '%')[0]}} | ConvertTo-Json -Compress"))
        report['baseline'] = baseline
        with virtual.open_sftp() as transfer:
            for name in ('dual_stack_pilot.py', 'capture_probe_ra.py'):
                transfer.put(str(Path(__file__).with_name(name)), '/tmp/' + run_id + '-' + name)
        launch = ['python3', '/tmp/' + run_id + '-dual_stack_pilot.py', '--run', '--automatic',
                  '--external-control', control, '--physical-client', arguments.host, '--physical-mac', peer['MAC'],
                  '--unicast-ra-peer', peer['LinkLocal'], '--unicast-ra-prefix', prefix,
                  '--uplink-address', arguments.uplink_address]
        root('install -d -m 700 /var/log/failsafe4g-pilot; umask 077; nohup timeout --signal=TERM --kill-after=15 330 ' +
             ' '.join(shlex.quote(value) for value in launch) + f' > {log} 2>&1 < /dev/null & echo $!')
        started = True
        deadline = time.monotonic() + 60
        current = None
        while time.monotonic() < deadline:
            current = status()
            if current:
                break
            time.sleep(1)
        if not current:
            raise RuntimeError('Pilot failed to start: ' + root('tail -n 20 ' + log))
        capture = ['python3', '/tmp/' + run_id + '-capture_probe_ra.py', '--interface', 'enp0s5',
                   '--source-mac', current['gateway_mac'], '--target-mac', peer['MAC'],
                   '--target-ipv6', peer['LinkLocal'], '--output', control + '/wire.jsonl', '--seconds', '180']
        capture_pid = int(root('nohup ' + ' '.join(shlex.quote(value) for value in capture) + f' > {control}/capture.log 2>&1 < /dev/null & echo $!'))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if root(f'if [ -s {control}/wire.jsonl ]; then head -n 1 {control}/wire.jsonl; fi'):
                break
            time.sleep(0.3)
        else:
            raise RuntimeError('Probe-only wire capture did not become ready')
        action('Arm')
        action('PrepareRA', f"-ProbePrefix '{prefix}' -IPv6Gateway '{current['ipv6_gateway']}'")
        prepared = True
        print('Baseline and SYSTEM rollback verified; sending only client-addressed unicast RAs', flush=True)
        send(0, 15)
        time.sleep(2)
        learned = action('ReadRA')
        report['learned'] = learned
        if not learned['Addresses'] or any(address['PrefixOrigin'] != 4 for address in learned['Addresses']):
            raise RuntimeError('Windows did not obtain the probe SLAAC prefix')
        if learned['Router']:
            raise RuntimeError('Zero-lifetime advertisement incorrectly installed a default router')
        report['rdnss_ingested'] = dns_address in (learned.get('DNS') or [])
        report['rdnss_initial_zero_lifetime'] = report['rdnss_ingested']
        dns_check()
        report['passed'].append('Windows learned a real SLAAC prefix from zero-default-lifetime unicast RAs; local IPv6 UDP/TCP DNS works')
        positive = send(30, 15, preference=1)
        active = action('ReadRA')
        report['active'] = active
        report['rdnss_ingested'] = report['rdnss_ingested'] or dns_address in (active.get('DNS') or [])
        if not active['Router']:
            raise RuntimeError('Windows did not install the short-lived probe default router')
        removed = send(0, 15)
        withdrawn = action('ReadRA')
        report['withdrawn'] = withdrawn
        if withdrawn['Router'] or not withdrawn['Addresses']:
            raise RuntimeError('Default withdrawal failed or removed local SLAAC addresses')
        if removed['sent_monotonic'] - positive['sent_monotonic'] >= 30:
            raise RuntimeError('Withdrawal timing overlapped natural expiry; no conclusive withdrawal result')
        dns_check()
        report['passed'].append('Windows installed then withdrew the probe default router while preserving local SLAAC and DNS')
        print('SLAAC and default-router withdrawal passed; checking natural DNS/router expiry', flush=True)
        send(15, 15, preference=1)
        time.sleep(20)
        expired = action('ReadRA')
        report['expired'] = expired
        if expired['Router'] or dns_address in (expired.get('DNS') or []):
            raise RuntimeError('Probe default router or RDNSS did not expire')
        if not expired['Addresses']:
            raise RuntimeError('Short router/DNS expiry removed still-valid local SLAAC addresses')
        report['passed'].append('Router and RDNSS lifetimes expire independently of still-valid local IPv6 addressing')
        if not report['rdnss_ingested']:
            raise RuntimeError('SLAAC passed but Windows did not ingest RDNSS; investigate before deployment')
        send(0, 0, True)
        powershell(windows, f"Start-ScheduledTask -TaskName 'Failsafe4G-Rollback-{run_id}'")
        deadline = time.monotonic() + 40
        receipt = None
        while time.monotonic() < deadline:
            output = powershell(windows, f"if(Test-Path -LiteralPath '{directory}\\restored.json') {{ Get-Content -LiteralPath '{directory}\\restored.json' -Raw }}")
            if output:
                receipt = json.loads(output)
                break
            time.sleep(0.5)
        if not receipt or not receipt['Matched']:
            raise RuntimeError('SYSTEM rollback did not restore RA state to the baseline')
        report['passed'].append('Local SYSTEM rollback removed actual learned probe state and verified the baseline')
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        try:
            if prepared:
                try:
                    send(0, 0, True)
                finally:
                    restored = action('Restore')
                    report['restoration'] = restored
                    if not restored['Matched']:
                        raise RuntimeError('Windows baseline mismatch; leave rollback task armed')
            if task_armed and action('Verify')['Matched']:
                action('Disarm')
                task_armed = False
            if started:
                request_id += 1
                payload = base64.b64encode(json.dumps({'id': request_id, 'action': 'stop'}).encode()).decode()
                root(f"printf '%s' {payload} | base64 -d > {control}/command.new; mv {control}/command.new {control}/command.json")
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if 'pilot removed; host routes, rules, firewall and forwarding match baseline' in root('cat ' + log):
                        report['passed'].append('VM probe stopped with host networking restored')
                        break
                    time.sleep(0.5)
                else:
                    raise RuntimeError('VM cleanup was not confirmed')
                wire = [json.loads(line) for line in root('cat ' + control + '/wire.jsonl').splitlines()]
                records = [entry for entry in wire if 'confined' in entry]
                report['wire_capture'] = records
                if not records or not all(entry['confined'] for entry in records):
                    raise RuntimeError('Wire capture did not confirm client-only unicast confinement')
                report['passed'].append('Wire capture confirms every observed probe RA targeted only the selected client, with hop limit 255')
            if not action('Verify')['Matched']:
                raise RuntimeError('Final Windows baseline changed after probe shutdown')
        finally:
            if capture_pid:
                capture_script = '/tmp/' + run_id + '-capture_probe_ra.py'
                root(f"if [ -r /proc/{capture_pid}/cmdline ] && tr '\\0' ' ' < /proc/{capture_pid}/cmdline | grep -F -q -- {shlex.quote(capture_script)}; then kill {capture_pid}; fi")
            Path(arguments.report).write_text(json.dumps(report, indent=2), encoding='utf-8')
            windows.close()
            virtual.close()
    print(json.dumps({'passed': report['passed'], 'rdnss_ingested': report['rdnss_ingested'],
                      'production_ready': False}, indent=2))


if __name__ == '__main__':
    main()
