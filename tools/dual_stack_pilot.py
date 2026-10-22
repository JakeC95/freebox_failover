#!/usr/bin/env python3
"""Bounded Internet-connected namespace pilot, not a household failover service."""

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
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


class PilotFamilyHealth:
    def __init__(self):
        self.available = True
        self.successes = 0
        self.failures = 0

    def update(self, healthy):
        self.successes = self.successes + 1 if healthy is True else 0
        self.failures = self.failures + 1 if healthy is False else 0
        if self.failures >= 3:
            self.available = False
        elif self.successes >= 3:
            self.available = True
        return self.available


def command(*arguments, timeout=45, required=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError(f"Command {arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout


def unicast_packet(state, source, source_mac):
    from scapy.all import Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr
    from scapy.all import ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS
    peer = ipaddress.IPv6Address(state['unicast_ra_peer'])
    prefix = ipaddress.IPv6Network(state['unicast_ra_prefix'])
    origin = ipaddress.IPv6Address(source)
    target_mac = state['physical_mac']
    if not peer.is_link_local or not origin.is_link_local or peer == origin:
        raise ValueError('Distinct link-local source and destination addresses are required')
    if prefix.prefixlen != 64 or prefix.network_address.packed[0] != 253:
        raise ValueError('Use a dedicated fd00::/8 /64')
    for mac in (target_mac, source_mac):
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or int(mac.split(':')[0], 16) & 1 or mac == '00:00:00:00:00:00':
            raise ValueError('Only explicit nonzero unicast Ethernet addresses are permitted')
    if source_mac == target_mac:
        raise ValueError('Probe must not impersonate the client')
    lifetime, dns_lifetime = state['probe_router_lifetime'], state['probe_dns_lifetime']
    retire = state.get('probe_retire_prefix', False)
    preference = state.get('probe_router_preference', 3)
    if type(lifetime) is not int or type(dns_lifetime) is not int or lifetime not in (0, 15, 30) or dns_lifetime not in (0, 15) or not isinstance(retire, bool) or type(preference) is not int or preference not in (1, 3):
        raise ValueError('Probe requires bounded lifetimes, explicit high/low preference and boolean retirement')
    packet = (Ether(src=source_mac, dst=target_mac) /
              IPv6(src=str(origin), dst=str(peer), hlim=255) /
              ICMPv6ND_RA(routerlifetime=lifetime, prf=preference) /
              ICMPv6NDOptSrcLLAddr(lladdr=source_mac) /
              ICMPv6NDOptPrefixInfo(prefix=str(prefix.network_address), prefixlen=64,
                                   validlifetime=0 if retire else 120, preferredlifetime=0 if retire else 60) /
              ICMPv6NDOptRDNSS(lifetime=dns_lifetime, dns=[str(prefix.network_address + 1)]))
    decoded = Ether(bytes(packet))
    if decoded.dst != target_mac or decoded[IPv6].dst != str(peer) or decoded[IPv6].hlim != 255:
        raise RuntimeError('Unicast destination validation failed')
    return packet


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
    elif action == "announce-client":
        origin = get_if_hwaddr("wan0")
        sendp(Ether(src=origin, dst=state["physical_mac"]) /
              ARP(op=2, hwsrc=origin, psrc=state["uplink_ip"],
                  hwdst=state["physical_mac"], pdst=state["physical_client"]),
              iface="wan0", count=2, inter=0.2, verbose=False)
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
                  ICMPv6ND_RA(routerlifetime=30 if state["phase"] == "primary" and state.get("ipv6_available", True) else 0) /
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

        def ipv6_health():
            started = time.monotonic()
            context = ssl.create_default_context()
            for destination in ("2606:4700:4700::1111", "2606:4700:4700::1001"):
                try:
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
                        connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x76)
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
                            if bytes(response).split(b"\r\n", 1)[0] in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"):
                                return {"healthy": True, "https": True, "seconds": round(time.monotonic() - started, 2)}
                except (OSError, ssl.SSLError):
                    pass
            return {"healthy": False, "https": False, "seconds": round(time.monotonic() - started, 2)}

        with ThreadPoolExecutor(max_workers=3) as executor:
            primary = executor.submit(path_health, "primary", 0x71)
            backup = executor.submit(path_health, "backup", 0x72)
            primary6 = executor.submit(ipv6_health)
            print(json.dumps({"primary": primary.result(), "backup": backup.result(),
                              "primary_ipv6": primary6.result()}))
    elif action == "unicast-ra":
        addresses = json.loads(command('ip', '-j', '-6', 'addr', 'show', 'dev', 'wan0'))
        source = next(address['local'] for interface in addresses for address in interface['addr_info'] if address['scope'] == 'link')
        packet = unicast_packet(state, source, get_if_hwaddr('wan0'))
        sendp(packet, iface='wan0', count=2, inter=3.2, verbose=False)
        state['unicast_sent'] = True
        temporary = state_file.with_suffix('.new')
        temporary.write_text(json.dumps(state))
        temporary.replace(state_file)
        print(json.dumps({'unicast_packets_sent': 2, 'multicast_packets_sent': 0,
                          'router_lifetime': state['probe_router_lifetime'],
                          'dns_lifetime': state['probe_dns_lifetime'], 'sent_monotonic': time.monotonic()}))
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

        listeners = [("10.231.71.1", socketserver.ThreadingUDPServer, socketserver.ThreadingTCPServer),
                     ("fd42:4242:71::1", UDP6, TCP6)]
        if state.get("physical_client"):
            listeners.append((state["uplink_ip"], socketserver.ThreadingUDPServer, socketserver.ThreadingTCPServer))
        if state.get('unicast_ra_peer'):
            listeners.append((str(ipaddress.IPv6Network(state['unicast_ra_prefix']).network_address + 1), UDP6, TCP6))
        for address, udp_type, tcp_type in listeners:
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
    if arguments.external_control:
        if not arguments.automatic or not arguments.physical_client or not arguments.physical_mac:
            raise ValueError("External control requires automatic mode and an explicit physical client IP/MAC")
        if ipaddress.IPv4Address(arguments.physical_client) not in uplink.network:
            raise ValueError("Physical client must be on the upstream LAN")
        if arguments.physical_client in (str(uplink.ip), arguments.primary, arguments.backup):
            raise ValueError("Physical client cannot be a gateway or pilot uplink address")
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", arguments.physical_mac) or int(arguments.physical_mac[:2], 16) & 1 or arguments.physical_mac == '00:00:00:00:00:00':
            raise ValueError("Physical MAC must be a nonzero unicast lowercase Ethernet address")
    elif arguments.physical_client or arguments.physical_mac:
        raise ValueError("Physical clients require bounded external control")
    if arguments.unicast_ra_peer:
        if not arguments.external_control or not ipaddress.IPv6Address(arguments.unicast_ra_peer).is_link_local:
            raise ValueError('Unicast RA requires external control and a link-local peer')
        prefix = ipaddress.IPv6Network(arguments.unicast_ra_prefix)
        if prefix.prefixlen != 64 or prefix.network_address.packed[0] != 253:
            raise ValueError('Use a dedicated fd00::/8 /64 for unicast probing')
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
        if arguments.physical_client:
            state["physical_client"] = arguments.physical_client
            state['physical_mac'] = arguments.physical_mac
        if arguments.unicast_ra_peer:
            state.update(unicast_ra_peer=arguments.unicast_ra_peer,
                         unicast_ra_prefix=arguments.unicast_ra_prefix)
        state_file.write_text(json.dumps(state))
        decision = PilotDecision(time.monotonic())
        family_health = PilotFamilyHealth()
        faults = set()

        def update_ipv6_route(phase, available):
            if phase == "primary" and available:
                inside(gateway, "ip", "-6", "route", "del", "unreachable", "default", "metric", "1", required=False)
            else:
                inside(gateway, "ip", "-6", "route", "replace", "unreachable", "default", "metric", "1")

        def wait_ipv6_default(available):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                routes = json.loads(inside(client, "ip", "-j", "-6", "route", "show", "default"))
                if bool(routes) == available:
                    return
                time.sleep(0.25)
            raise RuntimeError("Pilot client RA transition timed out")

        def set_phase(phase):
            print(f"Pilot phase: {phase}", file=sys.stderr, flush=True)
            current = json.loads(state_file.read_text())
            current["phase"] = phase
            temporary = state_file.with_suffix(".new")
            inside(gateway, "ip", "route", "replace", "default", "via", current[phase], "dev", "wan0")
            available = phase == "primary" and current.get("ipv6_available", True)
            update_ipv6_route(phase, available)
            temporary.write_text(json.dumps(current))
            temporary.replace(state_file)
            wait_ipv6_default(available)

        def inject_fault(name, enabled):
            if name == "client_ipv6_blackhole" and not arguments.physical_client:
                raise ValueError("Silent-drop testing requires an explicit physical client")
            if enabled:
                faults.add(name)
            else:
                faults.discard(name)
            inside(gateway, "nft", "flush", "chain", "inet", "pilot", "fault_output")
            inside(gateway, "nft", "flush", "chain", "inet", "pilot", "fault_forward")
            inside(gateway, "nft", "flush", "chain", "inet", "pilot", "fault_prerouting")
            for path in sorted(faults):
                marks = {"primary": ("0x71", "0x76"), "backup": ("0x72",), "primary_ipv6": ("0x76",), "client_ipv6_blackhole": ()}[path]
                for mark in marks:
                    inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_output",
                           "meta", "mark", mark, "counter", "reject")
            if "client_ipv6_blackhole" in faults:
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_prerouting",
                       "iifname", "wan0", "ether", "saddr", arguments.physical_mac,
                       "ip6", "saddr", "2000::/3", "ip6", "daddr", "2000::/3", "counter", "drop")
            if faults.intersection(("primary", "primary_ipv6")):
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_forward",
                       "iifname", "lan0", "meta", "nfproto", "ipv6", "counter", "reject")
                if arguments.physical_client:
                    inside(gateway, "nft", "add", "rule", "inet", "pilot", "fault_forward",
                           "meta", "mark", "0x73", "meta", "nfproto", "ipv6", "counter", "reject")
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
            available = family_health.update(health["primary_ipv6"]["healthy"])
            current = json.loads(state_file.read_text())
            if available != current.get("ipv6_available", True):
                current["ipv6_available"] = available
                update_ipv6_route(decision.phase, available)
                temporary = state_file.with_suffix(".new")
                temporary.write_text(json.dumps(current))
                temporary.replace(state_file)
                wait_ipv6_default(decision.phase == "primary" and available)
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

        def unicast_ra(router_lifetime, dns_lifetime, retire=False, preference=3):
            if not arguments.unicast_ra_peer or router_lifetime not in (0, 15, 30) or dns_lifetime not in (0, 15):
                raise ValueError('Unicast probe not enabled or invalid lifetime')
            current = json.loads(state_file.read_text())
            current.update(probe_router_lifetime=router_lifetime, probe_dns_lifetime=dns_lifetime,
                           probe_retire_prefix=retire, probe_router_preference=preference)
            temporary = state_file.with_suffix('.new')
            temporary.write_text(json.dumps(current))
            temporary.replace(state_file)
            return json.loads(inside(gateway, 'python3', script, '--worker', 'unicast-ra', '--state', str(state_file)))

        def serve_external():
            control = Path(arguments.external_control).resolve()
            if control.parent != Path('/run') or not control.name.startswith('failsafe4g-physical-'):
                raise ValueError("External control must use its own /run/failsafe4g-physical-* directory")
            control.mkdir(mode=0o700)
            addresses = json.loads(inside(gateway, "ip", "-j", "-6", "addr", "show", "dev", "wan0"))
            link_local = next(address["local"] for interface in addresses for address in interface["addr_info"]
                              if address["scope"] == "link")
            gateway_mac = json.loads(inside(gateway, 'ip', '-j', 'link', 'show', 'dev', 'wan0'))[0]['address']
            last_id = 0
            last_ra = None
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                request_path = control / 'command.json'
                if request_path.exists():
                    request = json.loads(request_path.read_text())
                    if request['id'] > last_id:
                        if request['action'] == 'fault' and request['path'] in ('primary', 'backup', 'primary_ipv6', 'client_ipv6_blackhole') and isinstance(request['enabled'], bool):
                            inject_fault(request['path'], request['enabled'])
                        elif request['action'] == 'unicast_ra':
                            last_ra = unicast_ra(request['router_lifetime'], request['dns_lifetime'], request.get('retire_prefix', False), request.get('preference', 3))
                        elif request['action'] == 'stop':
                            passed.append('externally controlled physical-client pilot stopped for cleanup')
                            return
                        else:
                            raise ValueError('Invalid external pilot command')
                        last_id = request['id']
                health = automatic_step()
                status = {'ready': True, 'phase': decision.phase, 'reason': decision.reason,
                          'health': health, 'faults': sorted(faults), 'acknowledged_id': last_id,
                          'ipv6_available': decision.phase == 'primary' and family_health.available,
                          'ipv6_gateway': link_local, 'gateway': str(uplink.ip),
                          'namespace': gateway, 'transitions': transitions, 'unicast_ra': last_ra,
                          'gateway_mac': gateway_mac}
                temporary = control / 'status.new'
                temporary.write_text(json.dumps(status))
                temporary.replace(control / 'status.json')
            raise RuntimeError('External pilot reached its five-minute lifetime limit')

        try:
            for namespace in (gateway, client):
                command("ip", "netns", "add", namespace)
                created.append(namespace)
                inside(namespace, "ip", "link", "set", "lo", "up")
            command("ip", "link", "add", "link", arguments.interface, "name", "f4gpwan",
                    "netns", gateway, "type", "macvlan" if arguments.physical_client else "ipvlan",
                    "mode", "bridge" if arguments.physical_client else "l2")
            inside(gateway, "ip", "link", "set", "f4gpwan", "name", "wan0")
            inside(gateway, "ip", "link", "set", "wan0", "addrgenmode", "random")
            inside(gateway, "sysctl", "-qw", "net.ipv4.ip_forward=1",
                   "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.wan0.accept_ra=2")
            if arguments.physical_client:
                inside(gateway, "sysctl", "-qw", "net.ipv4.conf.all.send_redirects=0", "net.ipv4.conf.wan0.send_redirects=0")
            inside(gateway, "ip", "link", "set", "wan0", "up")
            inside(gateway, "python3", script, "--worker", "address-check", "--state", str(state_file))
            inside(gateway, "ip", "addr", "add", str(uplink), "dev", "wan0")
            if arguments.physical_client:
                inside(gateway, "python3", script, "--worker", "announce-client", "--state", str(state_file))
            if arguments.unicast_ra_peer:
                prefix = ipaddress.IPv6Network(arguments.unicast_ra_prefix)
                inside(gateway, 'ip', '-6', 'addr', 'add', str(prefix.network_address + 1) + '/64', 'dev', 'wan0')
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
            if arguments.automatic:
                native_routes = json.loads(inside(gateway, "ip", "-j", "-6", "route", "show", "default"))
                native_gateway = next(route["gateway"] for route in native_routes if route.get("dev") == "wan0" and "gateway" in route)
                inside(gateway, "ip", "-6", "route", "add", "table", "7176", "default", "via", native_gateway, "dev", "wan0")
                inside(gateway, "ip", "-6", "rule", "add", "priority", "7176", "fwmark", "0x76", "lookup", "7176")
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
                for hook in ("output", "forward", "prerouting"):
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
                if arguments.physical_client:
                    inside(gateway, "nft", "add", "rule", "inet", "pilot", "input",
                           "iifname", "wan0", "ip", "saddr", arguments.physical_client,
                           protocol, "dport", "53", "counter", "accept")
                if arguments.unicast_ra_peer:
                    inside(gateway, 'nft', 'add', 'rule', 'inet', 'pilot', 'input',
                           'iifname', 'wan0', 'ether', 'saddr', arguments.physical_mac,
                           'meta', 'nfproto', 'ipv6', protocol, 'dport', '53', 'counter', 'accept')
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
            if arguments.physical_client:
                inside(gateway, "nft", "add", "chain", "inet", "pilot", "physical_mark",
                       '{ type filter hook prerouting priority mangle; policy accept; }')
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "physical_mark",
                       "iifname", "wan0", "ether", "saddr", arguments.physical_mac,
                       "ip", "saddr", arguments.physical_client, "meta", "mark", "set", "0x73")
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "physical_mark",
                       "iifname", "wan0", "ether", "saddr", arguments.physical_mac,
                       "ip6", "saddr", "2000::/3", "meta", "mark", "set", "0x73")
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "forward",
                       "iifname", "wan0", "oifname", "wan0", "meta", "mark", "0x73", "counter", "accept")
                inside(gateway, "nft", "add", "chain", "inet", "pilot", "suppress_redirect",
                       '{ type filter hook output priority filter; policy accept; }')
                inside(gateway, "nft", "add", "rule", "inet", "pilot", "suppress_redirect",
                       "oifname", "wan0", "icmpv6", "type", "nd-redirect", "drop")
            for family, network in (("ip", "10.231.71.0/24"), ("ip6", "fd42:4242:71::/64")):
                inside(gateway, "nft", "add", "table", family, "pilot_nat")
                inside(gateway, "nft", "add", "chain", family, "pilot_nat", "postrouting",
                       '{ type nat hook postrouting priority srcnat; policy accept; }')
                inside(gateway, "nft", "add", "rule", family, "pilot_nat", "postrouting",
                       "oifname", "wan0", family, "saddr", network, "masquerade")
                if arguments.physical_client:
                    inside(gateway, "nft", "add", "rule", family, "pilot_nat", "postrouting",
                           "oifname", "wan0", "meta", "mark", "0x73", "masquerade")
            resolver.mkdir(mode=0o700, parents=True)
            resolver.joinpath("resolv.conf").write_text("nameserver 10.231.71.1\noptions timeout:3 attempts:2\n")
            spawn("dns")
            spawn("advertise")
            if arguments.external_control:
                set_phase("primary")
                check_dns()
                probe("-4")
                probe("-6")
                serve_external()
            else:
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
                        if not all(health[path]["healthy"] for path in ("primary", "backup", "primary_ipv6")):
                            raise RuntimeError("Both paths must pass warm-up probes before fault injection")
                    inject_fault("primary_ipv6", True)
                    for sample in range(2):
                        health = automatic_step()
                        if health["primary_ipv6"]["healthy"] or not family_health.available or decision.phase != "primary":
                            raise RuntimeError("Transient IPv6 failure was not independently debounced")
                    automatic_step()
                    if family_health.available or decision.phase != "primary" or transitions:
                        raise RuntimeError("IPv6-only outage must not switch working IPv4 to cellular")
                    check_dns()
                    if probe("-4")["ip"] != primary4["ip"] or probe()["ip"] != primary4["ip"]:
                        raise RuntimeError("IPv6-only outage lost primary IPv4/family fallback")
                    inside(client, "ping", "-6", "-c", "1", "-W", "2", "fd42:4242:71::1")
                    passed.append("IPv6-only failure withdraws pilot IPv6 default after debounce; fibre IPv4, DNS and local IPv6 remain usable without cellular takeover")
                    inject_fault("primary_ipv6", False)
                    for sample in range(2):
                        automatic_step()
                        if family_health.available:
                            raise RuntimeError("IPv6 recovery was not independently debounced")
                    automatic_step()
                    if not family_health.available or probe("-6")["ip"] != primary6["ip"] or transitions:
                        raise RuntimeError("Pinned native IPv6 health failed to restore pilot routing")
                    passed.append("IPv6 recovery is detected through a pinned native route while client default is withdrawn and restores only after three healthy samples")
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
            if arguments.unicast_ra_peer and json.loads(state_file.read_text()).get('unicast_sent'):
                try:
                    unicast_ra(0, 0, True)
                except Exception as error:
                    print('Unicast RA retirement failed: ' + str(error), file=sys.stderr)
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
    action.add_argument("--worker", choices=("address-check", "announce-client", "solicit", "advertise", "dns", "dns-check", "isolation-check", "health", "unicast-ra"), help=argparse.SUPPRESS)
    parser.add_argument("--state", help=argparse.SUPPRESS)
    parser.add_argument("--interface", default="enp0s5")
    parser.add_argument("--primary", default="192.168.1.254")
    parser.add_argument("--backup", default="192.168.1.253")
    parser.add_argument("--uplink-address", help="Required: checked unused address outside DHCP pool, with prefix")
    parser.add_argument("--automatic", action="store_true", help="Exercise automatic detection with pilot-only injected faults")
    parser.add_argument("--external-control", help="Private /run control directory for a bounded physical-client test")
    parser.add_argument("--physical-client", help="Explicit single-client IPv4 address; requires external control")
    parser.add_argument("--physical-mac", help="Explicit single-client Ethernet MAC; requires external control")
    parser.add_argument('--unicast-ra-peer', help='Explicit single-client link-local IPv6 address for bounded unicast probes')
    parser.add_argument('--unicast-ra-prefix', default='fd42:4242:72::/64', help='Dedicated ULA /64 for the optional unicast probe')
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
