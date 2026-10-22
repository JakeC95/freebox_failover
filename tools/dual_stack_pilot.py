#!/usr/bin/env python3
"""Bounded Internet-connected namespace pilot, not a household failover service."""

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time


class PilotDecision:
    def __init__(self, now, minimum_dwell=10):
        self.phase = "primary"
        self.changed = now
        self.minimum_dwell = minimum_dwell
        self.primary_up = 0
        self.primary_down = 0
        self.backup_up = 0
        self.reason = "starting"

    def update(self, primary, backup, now):
        self.primary_up = self.primary_up + 1 if primary is True else 0
        self.primary_down = self.primary_down + 1 if primary is False else 0
        self.backup_up = self.backup_up + 1 if backup is True else 0
        self.reason = "holding"
        desired = self.phase
        if primary is None or backup is None:
            self.reason = "probe_unknown"
        elif now - self.changed < self.minimum_dwell:
            self.reason = "minimum_dwell"
        elif self.phase == "primary" and self.primary_down >= 3:
            if self.backup_up >= 2:
                desired = "backup"
                self.reason = "primary_failed_backup_verified"
            else:
                self.reason = "backup_not_ready"
        elif self.phase == "backup" and self.primary_up >= 3:
            desired = "primary"
            self.reason = "primary_recovery_verified"
        elif primary is False and backup is False:
            self.reason = "both_paths_unavailable"
        if desired != self.phase:
            self.phase = desired
            self.changed = now
        return desired


def command(*arguments, timeout=45, required=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError(f"Command {arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout


def worker(action, state_path):
    namespace = command("ip", "netns", "identify").strip()
    if not namespace.startswith("f4g-pilot-"):
        raise RuntimeError("Worker requires a pilot namespace")
    state_file = Path(state_path)
    state = json.loads(state_file.read_text())
    from scapy.all import ARP, DNS, DNSQR, Ether, IPv6
    from scapy.all import ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
    from scapy.all import ICMPv6NDOptRDNSS, ICMPv6NDOptSrcLLAddr
    from scapy.all import get_if_hwaddr, sendp, srp1

    if action == "address-check":
        for attempt in range(3):
            conflict = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") /
                            ARP(op=1, psrc="0.0.0.0", pdst=state["uplink_ip"]),
                            iface="wan0", timeout=1, verbose=False)
            if conflict is not None:
                raise RuntimeError("Candidate address is in use; refusing to proceed")
    elif action == "solicit":
        addresses = json.loads(command("ip", "-j", "-6", "addr", "show", "dev", "wan0"))
        source = next(entry["local"] for interface in addresses
                      for entry in interface["addr_info"] if entry["scope"] == "link")
        sendp(Ether(dst="33:33:00:00:00:02") /
              IPv6(src=source, dst="ff02::2", hlim=255) / ICMPv6ND_RS() /
              ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr("wan0")),
              iface="wan0", verbose=False)
    elif action == "advertise":
        link = json.loads(command("ip", "-d", "-j", "link", "show", "lan0"))[0]
        if link.get("linkinfo", {}).get("info_kind") != "veth":
            raise RuntimeError("Advertisements are restricted to the private veth LAN")
        while True:
            state = json.loads(state_file.read_text())
            sendp(Ether(dst="33:33:00:00:00:01") /
                  IPv6(src="fe80::1", dst="ff02::1", hlim=255) /
                  ICMPv6ND_RA(routerlifetime=30 if state["phase"] == "primary" else 0) /
                  ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr("lan0")) /
                  ICMPv6NDOptPrefixInfo(prefix="fd42:4242:71::", prefixlen=64,
                                       validlifetime=3600, preferredlifetime=1800) /
                  ICMPv6NDOptRDNSS(lifetime=60, dns=["fd42:4242:71::1"]),
                  iface="lan0", verbose=False)
            time.sleep(5)
    elif action == "health":
        from concurrent.futures import ThreadPoolExecutor
        import ssl

        def path_health(name, mark):
            started = time.monotonic()
            dns_ok, https_ok = False, False
            query = bytes(DNS(id=4242, rd=1, qd=DNSQR(qname="www.cloudflare.com", qtype="A")))
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
                    connection.settimeout(2)
                    connection.connect((state[name], 53))
                    connection.send(query)
                    answer = DNS(connection.recv(65535))
                    dns_ok = answer.id == 4242 and answer.qr == 1 and answer.rcode == 0 and answer.ancount > 0
            except OSError:
                pass
            context = ssl.create_default_context()
            for destination in ("1.1.1.1", "1.0.0.1"):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                        connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
                        connection.settimeout(2)
                        connection.connect((destination, 443))
                        with context.wrap_socket(connection, server_hostname="one.one.one.one") as secure:
                            secure.sendall(b"GET /cdn-cgi/trace HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n")
                            response = bytearray()
                            while b"\r\n\r\n" not in response and len(response) < 8192:
                                chunk = secure.recv(1024)
                                if not chunk:
                                    break
                                response.extend(chunk)
                            https_ok = bytes(response).split(b"\r\n", 1)[0] in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK")
                    if https_ok:
                        break
                except (OSError, ssl.SSLError):
                    pass
            return {"healthy": bool(dns_ok and https_ok), "dns": bool(dns_ok),
                    "https": https_ok, "seconds": round(time.monotonic() - started, 2)}

        with ThreadPoolExecutor(max_workers=2) as executor:
            primary = executor.submit(path_health, "primary", 0x71)
            backup = executor.submit(path_health, "backup", 0x72)
            print(json.dumps({"primary": primary.result(), "backup": backup.result()}))
    elif action == "isolation-check":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            try:
                connection.connect((state["primary"], 80))
            except OSError as error:
                if error.errno not in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
                    raise
            else:
                raise RuntimeError("Pilot client unexpectedly reached household management")
    elif action == "dns-check":
        for address, family in (("10.231.71.1", socket.AF_INET), ("fd42:4242:71::1", socket.AF_INET6)):
            query = bytes(DNS(id=4242, rd=1, qd=DNSQR(qname="www.cloudflare.com", qtype="A")))
            for tcp in (False, True):
                with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
                    connection.settimeout(8)
                    connection.connect((address, 53))
                    if tcp:
                        connection.sendall(len(query).to_bytes(2, "big") + query)
                        answer = receive(connection, int.from_bytes(receive(connection, 2), "big"))
                    else:
                        connection.send(query)
                        answer = connection.recv(65535)
                decoded = DNS(answer)
                if decoded.id != 4242 or decoded.qr != 1 or decoded.rcode != 0 or decoded.ancount < 1:
                    raise RuntimeError("Pilot DNS response validation failed")
    elif action == "dns":
        def upstream(payload, tcp):
            current = json.loads(state_file.read_text())
            destination = current[current["phase"]]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
                connection.settimeout(4)
                connection.connect((destination, 53))
                if tcp:
                    connection.sendall(len(payload).to_bytes(2, "big") + payload)
                    length = int.from_bytes(receive(connection, 2), "big")
                    return receive(connection, length)
                connection.send(payload)
                return connection.recv(65535)

        class UDPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                payload, connection = self.request
                try:
                    connection.sendto(upstream(payload, False), self.client_address)
                except OSError:
                    pass

        class TCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                try:
                    length = int.from_bytes(receive(self.request, 2), "big")
                    answer = upstream(receive(self.request, length), True)
                    self.request.sendall(len(answer).to_bytes(2, "big") + answer)
                except OSError:
                    pass

        class UDP6(socketserver.ThreadingUDPServer):
            address_family = socket.AF_INET6

        class TCP6(socketserver.ThreadingTCPServer):
            address_family = socket.AF_INET6

        for address, udp_type, tcp_type in (("10.231.71.1", socketserver.ThreadingUDPServer,
                                           socketserver.ThreadingTCPServer),
                                          ("fd42:4242:71::1", UDP6, TCP6)):
            for server_type, handler in ((udp_type, UDPHandler), (tcp_type, TCPHandler)):
                server = server_type((address, 53), handler)
                threading.Thread(target=server.serve_forever, daemon=True).start()
        while True:
            time.sleep(60)


def receive(connection, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            raise OSError("Short DNS TCP response")
        chunks.extend(chunk)
    return bytes(chunks)


def run_pilot(arguments):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Explicit root execution on Linux is required")
    for gateway in (arguments.primary, arguments.backup):
        ipaddress.IPv4Address(gateway)
    if arguments.primary == arguments.backup:
        raise ValueError("Primary and backup must differ")
    uplink = ipaddress.IPv4Interface(arguments.uplink_address)
    if uplink.network.prefixlen > 30 or uplink.ip in (uplink.network.network_address, uplink.network.broadcast_address):
        raise ValueError("Pilot address must be an ordinary host address")
    if not uplink.ip.is_private or any(ipaddress.IPv4Address(address) not in uplink.network
                                      for address in (arguments.primary, arguments.backup)):
        raise ValueError("Use a checked private address on the upstream gateway subnet")
    if str(uplink.ip) in (arguments.primary, arguments.backup):
        raise ValueError("Pilot address must not be a gateway address")
    script = str(Path(__file__).resolve())
    prefix = f"f4g-pilot-{os.getpid()}"
    gateway, client = prefix + "-gw", prefix + "-client"
    created, processes, passed = [], [], []
    transitions = []
    resolver = Path("/etc/netns", client)
    resolver_parent_existed = resolver.parent.exists()
    started = time.monotonic()

    def inside(namespace, *values, **options):
        return command("ip", "netns", "exec", namespace, *values, **options)

    def snapshot():
        result = {}
        for family in ("-4", "-6"):
            routes = json.loads(command("ip", "-j", family, "route", "show", "table", "all"))
            for route in routes:
                route.pop("expires", None)
            result[family] = sorted(json.dumps(route, sort_keys=True) for route in routes)
        result["forwarding"] = command("sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
        result["rules"] = command("ip", "rule", "show")
        result["nft"] = command("nft", "list", "ruleset")
        return result

    baseline = snapshot()
    with tempfile.TemporaryDirectory(prefix=prefix + "-") as directory:
        state_file = Path(directory, "state.json")
        host_addresses = [entry["local"] for interface in json.loads(command("ip", "-j", "addr"))
                          for entry in interface["addr_info"]]
        if str(uplink.ip) in host_addresses:
            raise ValueError("Pilot address is already assigned to the host")
        state = {"primary": arguments.primary, "backup": arguments.backup, "phase": "primary",
                 "uplink_ip": str(uplink.ip)}
        state_file.write_text(json.dumps(state))
        decision = PilotDecision(time.monotonic())
        faults = set()

        def set_phase(phase):
            print(f"Pilot phase: {phase}", file=sys.stderr, flush=True)
            current = json.loads(state_file.read_text())
            current["phase"] = phase
            temporary = state_file.with_suffix(".new")
            inside(gateway, "ip", "route", "replace", "default", "via", current[phase], "dev", "wan0")
            if phase == "backup":
                inside(gateway, "ip", "-6", "route", "add", "unreachable", "default", "metric", "1")
            else:
                inside(gateway, "ip", "-6", "route", "del", "unreachable", "default", "metric", "1", required=False)
            temporary.write_text(json.dumps(current))
            temporary.replace(state_file)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                routes = json.loads(inside(client, "ip", "-j", "-6", "route", "show", "default"))
                if bool(routes) == (phase == "primary"):
                    return
                time.sleep(0.25)
            raise RuntimeError("Pilot client RA transition timed out")

        def inject_fault(name, enabled):
            if enabled:
                faults.add(name)
            else:
                faults.discard(name)
            inside(gateway, "nft", "flush", "chain", "inet", "pilot", "fault_output")
            inside(gateway, "nft", "flush", "chain", "inet", "pilot", "fault_forward")
            for path in sorted(faults):
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_output",
                       "meta", "mark", "0x71" if path == "primary" else "0x72", "counter", "reject")
            if "primary" in faults:
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_forward",
                       "iifname", "lan0", "meta", "nfproto", "ipv6", "counter", "reject")
            if decision.phase in faults:
                inside(gateway, "ip", "route", "replace", "unreachable", "default")
            else:
                inside(gateway, "ip", "route", "replace", "default", "via", state[decision.phase], "dev", "wan0")
            print(f"Pilot injected faults: {sorted(faults)}", file=sys.stderr, flush=True)

        def automatic_step():
            if any(process.poll() is not None for process in processes):
                raise RuntimeError("Pilot worker exited during automatic monitoring")
            health = json.loads(inside(gateway, "python3", script, "--worker", "health",
                                       "--state", str(state_file), timeout=25))
            previous = decision.phase
            desired = decision.update(health["primary"]["healthy"], health["backup"]["healthy"], time.monotonic())
            print(json.dumps({"health": health, "phase": desired, "reason": decision.reason}), file=sys.stderr, flush=True)
            if desired != previous:
                set_phase(desired)
                transitions.append({"from": previous, "to": desired,
                                    "reason": decision.reason,
                                    "elapsed_seconds": round(time.monotonic() - started, 1)})
            time.sleep(1)
            return health

        def wait_automatic(phase):
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline:
                automatic_step()
                if decision.phase == phase:
                    return
            raise RuntimeError(f"Automatic pilot failed to reach {phase}")

        def spawn(action):
            log = Path(directory, action + ".log").open("w")
            process = subprocess.Popen(["ip", "netns", "exec", gateway, "python3", script,
                                        "--worker", action, "--state", str(state_file)],
                                       stdout=log, stderr=log)
            log.close()
            processes.append(process)
            return process

        def probe(family=None):
            selection = [family] if family else []
            trace = inside(client, "curl", "--noproxy", "*", *selection, "--fail", "--silent",
                           "--show-error", "--connect-timeout", "8", "--max-time", "20",
                           "https://www.cloudflare.com/cdn-cgi/trace", timeout=25)
            values = dict(line.split("=", 1) for line in trace.splitlines() if "=" in line)
            if "ip" not in values or not values.get("tls", "").startswith("TLS"):
                raise RuntimeError("Invalid verified HTTPS trace")
            return values

        def check_dns():
            inside(client, "python3", script, "--worker", "dns-check", "--state", str(state_file), timeout=40)

        try:
            for namespace in (gateway, client):
                command("ip", "netns", "add", namespace)
                created.append(namespace)
                inside(namespace, "ip", "link", "set", "lo", "up")
            command("ip", "link", "add", "link", arguments.interface, "name", "f4gpwan",
                    "netns", gateway, "type", "ipvlan", "mode", "l2")
            inside(gateway, "ip", "link", "set", "f4gpwan", "name", "wan0")
            inside(gateway, "ip", "link", "set", "wan0", "addrgenmode", "random")
            inside(gateway, "sysctl", "-qw", "net.ipv4.ip_forward=1",
                   "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.wan0.accept_ra=2")
            inside(gateway, "ip", "link", "set", "wan0", "up")
            inside(gateway, "python3", script, "--worker", "address-check", "--state", str(state_file))
            inside(gateway, "ip", "addr", "add", str(uplink), "dev", "wan0")
            inside(gateway, "ip", "route", "add", "default", "via", arguments.primary)
            if arguments.automatic:
                for mark, table, upstream in (("0x71", "7171", arguments.primary), ("0x72", "7172", arguments.backup)):
                    inside(gateway, "ip", "route", "add", "table", table, str(uplink.network), "dev", "wan0")
                    inside(gateway, "ip", "route", "add", "table", table, "default", "via", upstream, "dev", "wan0")
                    inside(gateway, "ip", "rule", "add", "priority", table, "fwmark", mark, "lookup", table)
            time.sleep(2)
            inside(gateway, "python3", script, "--worker", "solicit", "--state", str(state_file))
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if json.loads(inside(gateway, "ip", "-j", "-6", "route", "show", "default")):
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("No upstream native IPv6 RA route; leaving household settings unchanged")
            inside(gateway, "ip", "link", "add", "lan0", "type", "veth", "peer", "name", "peer0")
            inside(gateway, "ip", "link", "set", "peer0", "netns", client)
            inside(client, "ip", "link", "set", "peer0", "name", "eth0")
            for namespace, interface in ((gateway, "lan0"), (client, "eth0")):
                inside(namespace, "sysctl", "-qw", f"net.ipv6.conf.{interface}.accept_dad=0")
                inside(namespace, "ip", "link", "set", interface, "up")
            inside(gateway, "ip", "addr", "add", "10.231.71.1/24", "dev", "lan0")
            inside(gateway, "ip", "-6", "addr", "add", "fd42:4242:71::1/64", "dev", "lan0")
            inside(gateway, "ip", "-6", "addr", "add", "fe80::1/64", "dev", "lan0")
            inside(client, "ip", "addr", "add", "10.231.71.2/24", "dev", "eth0")
            inside(client, "ip", "route", "add", "default", "via", "10.231.71.1")
            inside(client, "sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=1")
            inside(gateway, "nft", "add", "table", "inet", "pilot")
            if arguments.automatic:
                for hook in ("output", "forward"):
                    inside(gateway, "nft", "add", "chain", "inet", "pilot", "fault_" + hook,
                           f'{{ type filter hook {hook} priority -10; policy accept; }}')
            inside(gateway, "nft", "add", "chain", "inet", "pilot", "input",
                   '{ type filter hook input priority filter; policy drop; }')
            inside(gateway, "nft", "add", "rule", "inet", "pilot", "input",
                   "ct", "state", "established,related", "accept")
            inside(gateway, "nft", "add", "rule", "inet", "pilot", "input",
                   "iifname", "lo", "accept")
            inside(gateway, "nft", "add", "rule", "inet", "pilot", "input",
                   "meta", "l4proto", "ipv6-icmp", "accept")
            for protocol in ("udp", "tcp"):
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "input",
                       "iifname", "lan0", protocol, "dport", "53", "accept")
            inside(gateway, "nft", "add", "chain", "inet", "pilot", "forward",
                   '{ type filter hook forward priority filter; policy drop; }')
            inside(gateway, "nft", "add", "rule", "inet", "pilot", "forward",
                   "ct", "state", "established,related", "accept")
            for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"):
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "forward",
                       "iifname", "lan0", "ip", "daddr", network, "counter", "reject")
            upstream_addresses = json.loads(inside(gateway, "ip", "-j", "-6", "addr", "show", "dev", "wan0"))
            protected_prefixes = {"fc00::/7", "fe80::/10"}
            for interface in upstream_addresses:
                for address in interface["addr_info"]:
                    if address["scope"] == "global":
                        protected_prefixes.add(str(ipaddress.IPv6Interface(
                            f"{address['local']}/{address['prefixlen']}").network))
            for network in sorted(protected_prefixes):
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "forward",
                       "iifname", "lan0", "ip6", "daddr", network, "counter", "reject")
            inside(gateway, "nft", "add", "rule", "inet", "pilot", "forward",
                   "iifname", "lan0", "oifname", "wan0", "accept")
            for family, network in (("ip", "10.231.71.0/24"), ("ip6", "fd42:4242:71::/64")):
                inside(gateway, "nft", "add", "table", family, "pilot_nat")
                inside(gateway, "nft", "add", "chain", family, "pilot_nat", "postrouting",
                       '{ type nat hook postrouting priority srcnat; policy accept; }')
                inside(gateway, "nft", "add", "rule", family, "pilot_nat", "postrouting",
                       "oifname", "wan0", family, "saddr", network, "masquerade")
            resolver.mkdir(mode=0o700, parents=True)
            resolver.joinpath("resolv.conf").write_text("nameserver 10.231.71.1\noptions timeout:3 attempts:2\n")
            spawn("dns")
            spawn("advertise")
            set_phase("primary")
            inside(client, "python3", script, "--worker", "isolation-check", "--state", str(state_file))
            rules = json.loads(inside(gateway, "nft", "-j", "list", "chain", "inet", "pilot", "forward"))
            rejected = sum(expression.get("counter", {}).get("packets", 0)
                           for entry in rules["nftables"] for expression in entry.get("rule", {}).get("expr", []))
            if not rejected:
                raise RuntimeError("Household isolation reject rule was not exercised")
            passed.append("pilot client household-management access rejected by counted firewall rule")
            check_dns()
            primary4, primary6 = probe("-4"), probe("-6")
            passed.append("separate pilot client: UDP/TCP DNS over IPv4/IPv6 and verified HTTPS through fibre over both families")
            if arguments.automatic:
                for sample in range(3):
                    health = automatic_step()
                    if not all(health[path]["healthy"] for path in ("primary", "backup")):
                        raise RuntimeError("Both paths must pass warm-up probes before fault injection")
                inject_fault("primary", True)
                for sample in range(2):
                    health = automatic_step()
                    if health["primary"]["healthy"] or decision.phase != "primary":
                        raise RuntimeError("Transient primary failure was not correctly debounced")
                inject_fault("primary", False)
                automatic_step()
                passed.append("two failed primary samples do not trigger takeover; a healthy sample resets the failure streak")
                inject_fault("backup", True)
                health = automatic_step()
                if health["backup"]["healthy"] or not health["primary"]["healthy"]:
                    raise RuntimeError("Backup failure injection did not remain path-specific")
                inject_fault("primary", True)
                for sample in range(3):
                    health = automatic_step()
                    if health["primary"]["healthy"] or health["backup"]["healthy"] or decision.phase != "primary":
                        raise RuntimeError("Unavailable backup must not be selected during primary failure")
                passed.append("a failed cellular path prevents takeover even after sustained primary failure")
                inject_fault("backup", False)
                wait_automatic("backup")
                passed.append("automatic takeover requires sustained pinned-primary failure and verified cellular readiness")
            else:
                set_phase("backup")
            check_dns()
            backup4 = probe("-4")
            if backup4["ip"] == primary4["ip"]:
                raise RuntimeError("Backup egress did not differ from primary")
            failed6 = subprocess.run(["ip", "netns", "exec", client, "curl", "--noproxy", "*", "-6",
                                      "--silent", "--max-time", "5", "https://www.cloudflare.com/cdn-cgi/trace"],
                                     capture_output=True, timeout=8)
            if failed6.returncode == 0:
                raise RuntimeError("IPv6 unexpectedly remained reachable on IPv4-only backup")
            inside(client, "ping", "-6", "-c", "1", "-W", "2", "fd42:4242:71::1")
            passed.append("pilot-only backup: different cellular IPv4 egress, reachable DNS, IPv6 default withdrawn, local IPv6 retained")
            automatic = probe()
            if automatic["ip"] != backup4["ip"]:
                raise RuntimeError("Backup route changed unexpectedly")
            if arguments.automatic:
                inject_fault("backup", True)
                for sample in range(3):
                    health = automatic_step()
                    if health["primary"]["healthy"] or health["backup"]["healthy"] or decision.phase != "backup":
                        raise RuntimeError("Both-path failure must not bounce to the known-broken primary")
                inject_fault("backup", False)
                for sample in range(2):
                    automatic_step()
                passed.append("both-path failure holds state without oscillation; cellular health recovers independently")
                inject_fault("primary", False)
                for sample in range(2):
                    health = automatic_step()
                    if not health["primary"]["healthy"] or decision.phase != "backup":
                        raise RuntimeError("Primary recovery was not correctly debounced")
                inject_fault("primary", True)
                automatic_step()
                if decision.phase != "backup":
                    raise RuntimeError("A flapping primary caused premature recovery")
                passed.append("brief primary recovery followed by failure does not leave cellular")
                inject_fault("primary", False)
                wait_automatic("primary")
            else:
                set_phase("primary")
            check_dns()
            restored4, restored6 = probe("-4"), probe("-6")
            if restored4["ip"] != primary4["ip"] or restored6["ip"] != primary6["ip"]:
                raise RuntimeError("Primary egress was not restored")
            passed.append("primary IPv4/IPv6 gateway and DNS restored for pilot client")
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError("Pilot worker exited early")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            for namespace in reversed(created):
                command("ip", "netns", "del", namespace)
            if resolver.exists():
                resolver.joinpath("resolv.conf").unlink(missing_ok=True)
                resolver.rmdir()
            if not resolver_parent_existed and resolver.parent.exists():
                resolver.parent.rmdir()
    if snapshot() != baseline:
        raise RuntimeError("Host network state differs from baseline; inspect before proceeding")
    passed.append("pilot removed; host routes, rules, firewall and forwarding match baseline")
    print(json.dumps({"passed": passed, "seconds": round(time.monotonic() - started, 1),
                      "production_ready": False, "ipv6_design": "temporary ULA plus NAT66 on fibre only",
                      "transitions": transitions,
                      "switching": "automatic detection of namespace-injected faults" if arguments.automatic else "explicit pilot-only phases"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--run", action="store_true")
    action.add_argument("--worker", choices=("address-check", "solicit", "advertise", "dns", "dns-check", "isolation-check", "health"), help=argparse.SUPPRESS)
    parser.add_argument("--state", help=argparse.SUPPRESS)
    parser.add_argument("--interface", default="enp0s5")
    parser.add_argument("--primary", default="192.168.1.254")
    parser.add_argument("--backup", default="192.168.1.253")
    parser.add_argument("--uplink-address", help="Required: checked unused address outside DHCP pool, with prefix")
    parser.add_argument("--automatic", action="store_true", help="Exercise automatic detection with pilot-only injected faults")
    settings = parser.parse_args()
    if settings.run:
        if not settings.uplink_address:
            parser.error("--run requires --uplink-address after checking DHCP leases and static assignments")
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        signal.signal(signal.SIGHUP, lambda *_: sys.exit(129))
        import fcntl
        with Path("/run/failsafe-dual-stack-pilot.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run_pilot(settings)
    else:
        worker(settings.worker, settings.state)
