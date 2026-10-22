#!/usr/bin/env python3
"""Bounded Windows data-path acceptance; requires a proven local rollback guard."""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import shlex
import time

import paramiko


def powershell(client, code):
    code = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop';\n" + code
    encoded = base64.b64encode(code.encode('utf-16-le')).decode('ascii')
    stdin, stdout, stderr = client.exec_command(
        'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + encoded,
        timeout=90)
    stdin.close()
    output, errors = stdout.read().decode('utf-8-sig'), stderr.read().decode('utf-8-sig')
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Windows command failed: ' + errors)
    return output.strip()


def connect(host, user, known_hosts, **credentials):
    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=user, allow_agent=False, look_for_keys=False,
                   timeout=10, banner_timeout=10, auth_timeout=10, **credentials)
    return client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--known-hosts', required=True)
    parser.add_argument('--run-directory', required=True)
    parser.add_argument('--client-mac', required=True)
    parser.add_argument('--vm-host', required=True)
    parser.add_argument('--vm-key', required=True)
    parser.add_argument('--vm-known-hosts', required=True)
    parser.add_argument('--uplink-address', required=True)
    parser.add_argument('--report', required=True)
    arguments = parser.parse_args()
    run_id = Path(arguments.run_directory.replace('\\', '/')).name
    if not run_id.startswith('pilot-') or not run_id.removeprefix('pilot-').isdigit():
        raise ValueError('Expected a timestamped pilot run directory')
    control = '/run/failsafe4g-physical-' + run_id + '-' + str(os.getpid())
    script = '/tmp/failsafe4g-physical-' + run_id + '.py'
    log = '/var/log/failsafe4g-pilot/windows-' + run_id + '-' + str(os.getpid()) + '.log'
    guard = arguments.run_directory + '\\windows_client_pilot.ps1'
    if "'" in arguments.run_directory:
        raise ValueError('Unsupported run-directory quoting')
    request_id = 0
    process_started = False
    windows_changed = False
    report = {'passed': [], 'production_ready': False,
              'scope': 'real Windows routed data path; not isolated-LAN SLAAC/RA acceptance'}
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

    def client_action(action, extra=''):
        return json.loads(powershell(windows, f"& '{guard}' -Action {action} -RunDirectory '{arguments.run_directory}' {extra}"))

    def status():
        output = root(f'if [ -f {control}/status.json ]; then cat {control}/status.json; else echo null; fi')
        return json.loads(output)

    def wait_phase(phase):
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            current = status()
            if current and current['phase'] == phase and current['acknowledged_id'] == request_id:
                return current
            time.sleep(1)
        raise RuntimeError('Physical pilot did not reach ' + phase)

    def request(action, **values):
        nonlocal request_id
        request_id += 1
        payload = base64.b64encode(json.dumps({'id': request_id, 'action': action, **values}).encode()).decode()
        root(f"printf '%s' {payload} | base64 -d > {control}/command.new; mv {control}/command.new {control}/command.json")

    def dns_probe(gateway):
        powershell(windows, f"$answers=@(Resolve-DnsName www.cloudflare.com -Server '{gateway}' -Type A -DnsOnly -ErrorAction Stop); if (-not @($answers | Where-Object IPAddress).Count) {{ throw 'No UDP DNS answer' }}; $answers=@(Resolve-DnsName www.cloudflare.com -Server '{gateway}' -Type A -DnsOnly -TcpOnly -ErrorAction Stop); if (-not @($answers | Where-Object IPAddress).Count) {{ throw 'No TCP DNS answer' }}; 'DNS_OK'")

    def https_probe(family):
        selection = family or ''
        output = powershell(windows, f"$trace=@(& curl.exe --noproxy '*' {selection} --fail --silent --show-error --connect-timeout 6 --max-time 18 https://www.cloudflare.com/cdn-cgi/trace); if ($LASTEXITCODE -ne 0) {{ throw 'Verified HTTPS failed' }}; $result=@{{}}; foreach ($line in $trace) {{ if ($line -match '^([^=]+)=(.*)$') {{ $result[$matches[1]]=$matches[2] }} }}; if (-not $result.ip -or -not $result.tls) {{ throw 'Invalid HTTPS trace' }}; $result | ConvertTo-Json -Compress")
        return json.loads(output)

    try:
        receipt = json.loads(powershell(windows, f"Get-Content -LiteralPath '{arguments.run_directory}\\restored.json' -Raw"))
        if not receipt['Matched']:
            raise RuntimeError('A successful local SYSTEM canary rollback is required')
        if not client_action('Verify')['Matched']:
            raise RuntimeError('Windows baseline changed before acceptance')
        baseline = json.loads(powershell(windows, f"Get-Content -LiteralPath '{arguments.run_directory}\\baseline.json' -Raw"))
        print('Windows rollback and baseline verified', flush=True)
        with virtual.open_sftp() as transfer:
            transfer.put(str(Path(__file__).with_name('dual_stack_pilot.py')), script)
        launch = ['python3', script, '--run', '--automatic', '--external-control', control,
                  '--physical-client', arguments.host, '--physical-mac', arguments.client_mac,
                  '--uplink-address', arguments.uplink_address]
        root('install -d -m 700 /var/log/failsafe4g-pilot; umask 077; nohup timeout --signal=TERM --kill-after=15 330 ' +
             ' '.join(shlex.quote(value) for value in launch) + f' > {log} 2>&1 < /dev/null & echo $!')
        process_started = True
        current = wait_phase('primary')
        report['gateway'] = current['gateway']
        print('Physical pilot ready; testing DNS before changing Windows routes', flush=True)
        dns_probe(current['gateway'])
        client_action('Arm')
        windows_changed = True
        client_action('Apply', f"-Gateway '{current['gateway']}' -IPv6Gateway '{current['ipv6_gateway']}'")
        primary4, primary6 = https_probe('-4'), https_probe('-6')
        original_addresses = {ipaddress.ip_address(address['IPAddress'].split('%')[0])
                              for address in baseline['Configuration']['Addresses']}
        if ipaddress.ip_address(primary6['ip']) in original_addresses:
            raise RuntimeError('IPv6 source bypassed the pilot NAT path')
        forwarding = json.loads(root(f"ip netns exec {current['namespace']} nft -j list chain inet pilot forward"))
        dns_counts = json.loads(root(f"ip netns exec {current['namespace']} nft -j list chain inet pilot input"))
        routed_packets = 0
        for entry in forwarding['nftables']:
            expressions = entry.get('rule', {}).get('expr', [])
            if any(expression.get('match', {}).get('left') == {'meta': {'key': 'mark'}}
                   and expression['match'].get('right') in (115, '0x00000073', '0x73') for expression in expressions):
                routed_packets += sum(expression.get('counter', {}).get('packets', 0) for expression in expressions)
        dns_packets = sum(expression.get('counter', {}).get('packets', 0)
                          for entry in dns_counts['nftables'] for expression in entry.get('rule', {}).get('expr', []))
        if not routed_packets or not dns_packets:
            raise RuntimeError('Physical-client forwarding and DNS counters were not exercised')
        report['pilot_counters'] = {'physical_forward_packets': routed_packets, 'physical_dns_packets': dns_packets}
        report['primary'] = {'ipv4': primary4['ip'], 'ipv6': primary6['ip']}
        report['passed'].append('real Windows IPv4/IPv6 certificate-verified HTTPS through pilot fibre path')
        print('Windows fibre IPv4/IPv6 passed; injecting pilot-only primary failure', flush=True)
        request('fault', path='primary', enabled=True)
        current = wait_phase('backup')
        dns_probe(current['gateway'])
        backup4, unforced = https_probe('-4'), https_probe(None)
        if backup4['ip'] == primary4['ip'] or unforced['ip'] != backup4['ip']:
            raise RuntimeError('Windows did not use distinct cellular IPv4 egress')
        powershell(windows, "$null=& curl.exe --noproxy '*' -6 --fail --silent --connect-timeout 3 --max-time 5 https://www.cloudflare.com/cdn-cgi/trace; if ($LASTEXITCODE -eq 0) { throw 'Unexpected IPv6 Internet success on IPv4-only backup' }; 'IPV6_UNAVAILABLE_AS_EXPECTED'")
        scoped = current['ipv6_gateway'] + '%' + str(baseline['Configuration']['InterfaceIndex'])
        powershell(windows, f"$null=& ping.exe -6 -n 1 -w 2000 '{scoped}'; if ($LASTEXITCODE -ne 0) {{ throw 'Local IPv6 failed' }}; 'LOCAL_IPV6_OK'")
        report['backup'] = {'ipv4': backup4['ip'], 'location': backup4.get('loc')}
        report['passed'].append('automatic cellular takeover, UDP/TCP DNS, unforced-family Windows HTTPS fallback and retained local IPv6')
        print('Windows cellular fallback passed; restoring primary probe path', flush=True)
        request('fault', path='primary', enabled=False)
        current = wait_phase('primary')
        dns_probe(current['gateway'])
        restored4, restored6 = https_probe('-4'), https_probe('-6')
        if restored4['ip'] != primary4['ip'] or restored6['ip'] != primary6['ip']:
            raise RuntimeError('Windows primary egress did not return')
        report['transitions'] = current['transitions']
        report['passed'].append('automatic fibre IPv4/IPv6 recovery from the real Windows client')
    finally:
        try:
            if windows_changed:
                restored = client_action('Restore')
                report['restoration'] = restored
                if not restored['Matched']:
                    raise RuntimeError('Windows restoration mismatch; leave local rollback armed')
                windows_changed = False
                client_action('Disarm')
                report['passed'].append('Windows static address, routes, DNS, IPv6 settings and NRPT match original baseline; rollback task removed')
            else:
                if client_action('Verify')['Matched']:
                    powershell(windows, f"if (Get-ScheduledTask -TaskName 'Failsafe4G-Rollback-{run_id}' -ErrorAction SilentlyContinue) {{ & '{guard}' -Action Disarm -RunDirectory '{arguments.run_directory}' }}")
            if process_started:
                request('stop')
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    contents = root('cat ' + shlex.quote(log))
                    if 'pilot removed; host routes, rules, firewall and forwarding match baseline' in contents:
                        report['passed'].append('VM pilot stopped and host network state restored')
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError('VM pilot cleanup was not confirmed; inspect private log')
        finally:
            Path(arguments.report).write_text(json.dumps(report, indent=2), encoding='utf-8')
            windows.close()
            virtual.close()
    print(json.dumps({'passed': report['passed'], 'production_ready': False}, indent=2))


if __name__ == '__main__':
    main()
