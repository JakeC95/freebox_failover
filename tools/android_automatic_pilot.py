#!/usr/bin/env python3
"""Phone-scoped rehearsal driven by the VM namespace pilot's health decisions."""

import json
from pathlib import Path
import shlex
import time
import uuid

import paramiko

from android_lte_pilot import backup_health, counters, query


def verify_transitions(transitions):
    observed = [(entry.get("from"), entry.get("to")) for entry in transitions]
    if observed != [("primary", "backup"), ("backup", "primary")]:
        raise RuntimeError("Expected exactly one automatic takeover and one recovery")


def ap_rules(table, interfaces, mac, address, network, primary_mac, router_mac):
    lines = [f"table netdev {table} {{"]
    for name in ("outage", "backup", "restricted"):
        lines.append(f" set {name} {{ type ether_addr; }}")
    match = f"ether saddr {mac} ether daddr {primary_mac} ip saddr {address}"
    for index, interface in enumerate(interfaces):
        lines.extend([
            f" chain wifi{index} {{",
            f'  type filter hook ingress device "{interface}" priority -500; policy accept;',
            f"  ether saddr {mac} ether saddr @restricted ether type ip6 ip6 daddr 2000::/3 counter drop;",
            f"  ether saddr {mac} ether saddr @restricted ether type ip6 meta l4proto {{ tcp, udp }} th dport 53 counter drop;",
            f"  {match} ether saddr @backup meta l4proto {{ tcp, udp }} th dport 53 counter ether daddr set {router_mac};",
            f"  {match} ether saddr @backup ip daddr != {network} counter ether daddr set {router_mac};",
            f"  {match} ether saddr @outage meta l4proto {{ tcp, udp }} th dport 53 counter drop;",
            f"  {match} ether saddr @outage ip daddr != {network} counter drop;",
            " }",
        ])
    return "\n".join(lines + ["}", ""])


class AutomaticPhonePilot:
    def __init__(self, arguments, report):
        self.arguments = arguments
        self.report = report
        self.client = None
        self.started = False
        self.request_id = 0
        self.identity = uuid.uuid4().hex[:12]
        self.control = "/run/failsafe4g-physical-android-" + self.identity
        self.base = "/var/log/failsafe4g-pilot/android-auto-" + self.identity
        report["automatic"] = {"events": [], "samples": [], "vm_cleanup_verified": False,
                               "scope": "namespace-injected health fault mirrored only to selected phone; not a physical fibre cut or production takeover"}
        self.details = report["automatic"]

    def root(self, command):
        return query(self.client, "sudo -n sh -c " + shlex.quote(command))[0].strip()

    def status(self):
        output = self.root(f"if [ -f {self.control}/status.json ]; then cat {self.control}/status.json; else echo null; fi")
        return json.loads(output)

    def request(self, enabled=None):
        self.request_id += 1
        payload = {"id": self.request_id, "action": "stop"} if enabled is None else {
            "id": self.request_id, "action": "fault", "path": "primary", "enabled": enabled}
        self.root(f"printf '%s' {shlex.quote(json.dumps(payload))} > {self.control}/command.new; "
                  f"mv {self.control}/command.new {self.control}/command.json")

    def start(self):
        self.client = paramiko.SSHClient()
        self.client.load_host_keys(self.arguments.vm_known_hosts)
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.client.connect(self.arguments.vm_host, username="freebox", key_filename=self.arguments.vm_key,
                            look_for_keys=False, allow_agent=False, timeout=8, banner_timeout=8, auth_timeout=8)
        temporary = "/tmp/failsafe4g-android-auto-" + self.identity + ".py"
        with self.client.open_sftp() as transfer:
            with transfer.open(temporary, "wx") as output:
                output.write(Path(__file__).with_name("dual_stack_pilot.py").read_bytes())
            transfer.chmod(temporary, 0o600)
        self.root(f"install -d -m 700 /var/log/failsafe4g-pilot; "
                  f"install -m 600 {temporary} {self.base}.py; rm -f {temporary}")
        launch = ["timeout", "--signal=TERM", "--kill-after=15", "300", "python3", self.base + ".py",
                  "--run", "--automatic", "--external-control", self.control,
                  "--physical-client", str(self.arguments.address), "--physical-mac", self.arguments.mac,
                  "--uplink-address", self.arguments.vm_uplink, "--backup", str(self.arguments.router)]
        worker = (" ".join(shlex.quote(value) for value in launch) +
                  f" > {self.base}.json 2> {self.base}.log; result=$?; printf '%s' \"$result\" > {self.base}.exit")
        self.started = True
        self.root("umask 077; nohup sh -c " + shlex.quote(worker) + " </dev/null >/dev/null 2>&1 &")
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            current = self.status()
            if current and current.get("ready"):
                if current["phase"] != "primary" or not all(current["health"][name]["healthy"]
                                                             for name in ("primary", "backup", "primary_ipv6")):
                    raise RuntimeError("VM pilot paths are not all healthy at baseline")
                self.details["baseline"] = current
                return
            if self.root(f"test ! -f {self.base}.exit || cat {self.base}.exit"):
                raise RuntimeError("VM pilot exited before readiness")
            time.sleep(1)
        raise RuntimeError("VM pilot readiness timed out")

    def event(self, stage, **fields):
        entry = {"stage": stage, "elapsed_seconds": round(time.monotonic() - self.began, 2), **fields}
        self.details["events"].append(entry)
        print(json.dumps(entry), flush=True)

    def mode(self, devices, table, outage, backup):
        lines = []
        for name, enabled in (("outage", outage), ("backup", backup), ("restricted", outage or backup)):
            lines.append(f"flush set netdev {table} {name}")
            if enabled:
                lines.append(f"add element netdev {table} {name} {{ {self.arguments.mac} }}")
        for host in self.arguments.ap:
            query(devices[host], "nft -f -", "\n".join(lines) + "\n")

    def sample(self, devices, table):
        current = self.status()
        if not current or not current.get("ready"):
            raise RuntimeError("VM decision heartbeat missing")
        if time.monotonic() >= self.expiry:
            raise RuntimeError("Automatic rehearsal exceeded the AP lifetime")
        if time.monotonic() >= self.next_health:
            healthy = backup_health(devices[str(self.arguments.router)], self.arguments.router, self.previous_uptime)
            self.previous_uptime = healthy["uptime"]
            self.report["backup_health"].append(healthy)
            self.next_health = time.monotonic() + 10
        for host, client in devices.items():
            observed = counters(client, self.report["devices"][host]["family"], table)
            if observed is None:
                raise RuntimeError("A rehearsal table expired unexpectedly")
            self.report["devices"][host]["last_counters"] = observed
        self.details["samples"].append(current)
        return current

    def hold(self, devices, table, seconds, phase):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.sample(devices, table)["phase"] != phase:
                raise RuntimeError("Unexpected decision change during stable observation")
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def wait(self, devices, table, phase):
        deadline = min(self.expiry, time.monotonic() + 35)
        while time.monotonic() < deadline:
            current = self.sample(devices, table)
            if current["phase"] == phase and current["acknowledged_id"] == self.request_id:
                return current
            time.sleep(1)
        raise RuntimeError("Automatic health decision did not reach " + phase)

    def exercise(self, devices, table):
        self.began = time.monotonic()
        self.expiry = self.began + self.arguments.seconds - 5
        self.next_health = 0
        self.previous_uptime = self.report["backup_health"][-1]["uptime"]
        self.event("automatic rehearsal baseline: phone on native fibre")
        self.hold(devices, table, 10, "primary")
        self.mode(devices, table, outage=True, backup=False)
        self.request(True)
        fault_started = time.monotonic()
        self.event("phone-only primary outage injected; waiting for VM health decision")
        current = self.wait(devices, table, "backup")
        self.mode(devices, table, outage=True, backup=True)
        self.event("automatic LTE switchover active", detection_seconds=round(time.monotonic() - fault_started, 2),
                   decision_reason=current["reason"], observation_seconds=60,
                   expected_public_ipv4=self.report["backup_health"][-1]["https_public_ip"])
        self.hold(devices, table, 60, "backup")
        self.mode(devices, table, outage=False, backup=True)
        self.request(False)
        recovery_started = time.monotonic()
        self.event("phone-only primary fault cleared; waiting for stable recovery")
        current = self.wait(devices, table, "primary")
        self.mode(devices, table, outage=False, backup=False)
        self.event("automatic native fibre recovery active", recovery_seconds=round(time.monotonic() - recovery_started, 2),
                   decision_reason=current["reason"])
        self.hold(devices, table, 10, "primary")
        current = self.sample(devices, table)
        self.details["transitions"] = current["transitions"]
        verify_transitions(current["transitions"])
        self.details["rehearsal_completed"] = True

    def close(self):
        if self.client is None:
            return
        try:
            if self.started:
                if self.status():
                    self.request()
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    result = self.root(f"if [ -f {self.base}.exit ]; then cat {self.base}.exit; else echo running; fi")
                    if result != "running":
                        if result != "0":
                            raise RuntimeError("VM pilot did not exit cleanly")
                        outcome = json.loads(self.root(f"cat {self.base}.json"))
                        if not any("host routes, rules, firewall and forwarding match baseline" in check
                                   for check in outcome["passed"]):
                            raise RuntimeError("VM host restoration was not verified")
                        self.details["vm_cleanup_verified"] = True
                        self.details["vm_result"] = outcome
                        return
                    time.sleep(1)
                raise RuntimeError("VM pilot stop timed out; bounded VM timeout remains armed")
        finally:
            self.client.close()
