#!/usr/bin/env python3
"""Bounded, single-client local forwarding/NAT benchmark; no Internet uplink."""

import argparse
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time


SIZE = 128 * 1024 * 1024
TARGET = "198.18.71.2"
PORT = 5201


def command(*arguments, required=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=15)
    if required and result.returncode:
        raise RuntimeError(f"{arguments[0]} returned {result.returncode}")
    return result.stdout.strip()


def snapshot():
    result = {}
    for family in ("-4", "-6"):
        routes = json.loads(command("ip", "-j", family, "route", "show", "table", "all"))
        for route in routes:
            route.pop("expires", None)
        result[family] = sorted(json.dumps(route, sort_keys=True) for route in routes)
        result[family + "rules"] = command("ip", family, "rule", "show")
    result["nft"] = command("nft", "list", "ruleset")
    result["forwarding"] = command("sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
    return result


def server(state):
    class Server(http.server.HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(15)
            return connection, address

    class Handler(http.server.BaseHTTPRequestHandler):
        transfers = 0

        def log_message(self, *arguments):
            pass

        def do_GET(self):
            self.connection.settimeout(15)
            if self.client_address[0] != "198.18.71.1" or self.path != "/" + state["token"] + "/download":
                self.send_error(404)
                return
            Handler.transfers += 1
            if Handler.transfers > 8:
                self.send_error(429)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(SIZE))
            self.end_headers()
            block = bytes(1024 * 1024)
            for position in range(SIZE // len(block)):
                self.wfile.write(block)

        def do_PUT(self):
            self.connection.settimeout(15)
            if self.client_address[0] != "198.18.71.1" or self.path != "/" + state["token"] + "/upload" or self.headers.get("Content-Length") != str(SIZE):
                self.send_error(400)
                return
            Handler.transfers += 1
            if Handler.transfers > 8:
                self.send_error(429)
                return
            remaining = SIZE
            while remaining:
                block = self.rfile.read(min(1024 * 1024, remaining))
                if not block:
                    raise RuntimeError("Incomplete upload")
                remaining -= len(block)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    with Server((TARGET, PORT), Handler) as listener:
        listener.timeout = 2
        deadline = time.monotonic() + 140
        while time.monotonic() < deadline:
            listener.handle_request()


def run(arguments):
    import fcntl
    from scapy.all import ARP, Ether, srp1

    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run on Linux as root")
    uplink = ipaddress.IPv4Interface(arguments.uplink_address)
    client = ipaddress.IPv4Address(arguments.client)
    if not uplink.ip.is_private or not 8 <= uplink.network.prefixlen <= 30 or client not in uplink.network or client == uplink.ip:
        raise ValueError("Use distinct client/uplink addresses on the checked private LAN")
    if uplink.ip in (uplink.network.network_address, uplink.network.broadcast_address):
        raise ValueError("Invalid uplink address")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", arguments.mac) or int(arguments.mac[:2], 16) & 1 or arguments.mac == "00:00:00:00:00:00":
        raise ValueError("Explicit nonzero unicast client MAC required")
    control = Path(arguments.control)
    if control.parent != Path("/run") or not re.fullmatch(r"failsafe4g-benchmark-[a-zA-Z0-9-]+", control.name):
        raise ValueError("Use a new /run/failsafe4g-benchmark-* control directory")
    addresses = json.loads(command("ip", "-j", "addr", "show"))
    if any(address.get("local") == str(uplink.ip) for interface in addresses for address in interface.get("addr_info", [])):
        raise ValueError("Candidate uplink is already assigned to the host")
    for attempt in range(3):
        if srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="0.0.0.0", pdst=str(uplink.ip)),
                iface=arguments.interface, timeout=1, verbose=False) is not None:
            raise RuntimeError("Candidate uplink address is in use")
    prefix = "f4g-bench-" + str(os.getpid())
    gateway, endpoint = prefix + "-gw", prefix + "-endpoint"
    created = []
    process = None
    baseline = snapshot()

    def inside(namespace, *values):
        return command("ip", "netns", "exec", namespace, *values)

    with Path("/run/failsafe-dual-stack-pilot.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        control.mkdir(mode=0o700)
        state = {"token": secrets.token_hex(16), "gateway": str(uplink.ip), "namespace": gateway,
                 "client": str(client), "mac": arguments.mac,
                 "cpu_count": os.cpu_count(), "host_link": json.loads(command("ip", "-j", "link", "show", "dev", arguments.interface))[0]}
        state_path = control / "state.json"

        def write_state():
            temporary = state_path.with_suffix(".new")
            temporary.write_text(json.dumps(state))
            temporary.replace(state_path)

        write_state()
        try:
            for namespace in (gateway, endpoint):
                command("ip", "netns", "add", namespace)
                created.append(namespace)
                inside(namespace, "ip", "link", "set", "lo", "up")
                inside(namespace, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
            command("ip", "link", "add", "link", arguments.interface, "name", "f4gbwan", "netns", gateway,
                    "type", "macvlan", "mode", "bridge")
            inside(gateway, "ip", "link", "set", "f4gbwan", "name", "uplink0")
            inside(gateway, "ip", "addr", "add", str(uplink), "dev", "uplink0")
            inside(gateway, "ip", "link", "set", "uplink0", "up")
            state["gateway_mac"] = json.loads(inside(gateway, "ip", "-j", "link", "show", "uplink0"))[0]["address"]
            inside(gateway, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.send_redirects=0")
            inside(gateway, "ip", "link", "add", "bench0", "type", "veth", "peer", "name", "peer0")
            inside(gateway, "ip", "link", "set", "peer0", "netns", endpoint)
            inside(gateway, "ip", "addr", "add", "198.18.71.1/30", "dev", "bench0")
            inside(endpoint, "ip", "addr", "add", TARGET + "/30", "dev", "peer0")
            for namespace, interface in ((gateway, "bench0"), (endpoint, "peer0")):
                inside(namespace, "ip", "link", "set", interface, "up")
            inside(endpoint, "ip", "route", "add", "default", "via", "198.18.71.1")
            inside(gateway, "nft", "add", "table", "inet", "bench")
            inside(gateway, "nft", "add", "chain", "inet", "bench", "input", "{ type filter hook input priority filter; policy drop; }")
            inside(gateway, "nft", "add", "chain", "inet", "bench", "forward", "{ type filter hook forward priority filter; policy drop; }")
            inside(gateway, "nft", "add", "rule", "inet", "bench", "forward", "iifname", "uplink0", "oifname", "bench0",
                   "ether", "saddr", arguments.mac, "ip", "saddr", str(client), "ip", "daddr", TARGET,
                   "tcp", "dport", str(PORT), "counter", "accept")
            inside(gateway, "nft", "add", "rule", "inet", "bench", "forward", "iifname", "bench0", "oifname", "uplink0",
                   "ip", "saddr", TARGET, "ip", "daddr", str(client), "ct", "state", "established,related", "counter", "accept")
            inside(gateway, "nft", "add", "table", "ip", "bench_nat")
            inside(gateway, "nft", "add", "chain", "ip", "bench_nat", "postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }")
            inside(gateway, "nft", "add", "rule", "ip", "bench_nat", "postrouting", "oifname", "bench0",
                   "ip", "saddr", str(client), "ip", "daddr", TARGET, "tcp", "dport", str(PORT), "counter", "snat", "to", "198.18.71.1")
            if inside(gateway, "ip", "route", "show", "default"):
                raise RuntimeError("Benchmark gateway must have no Internet default route")
            state["no_internet_default"] = True
            with (control / "server.log").open("w") as output:
                process = subprocess.Popen(["ip", "netns", "exec", endpoint, "python3", str(Path(__file__).resolve()),
                                            "--server", "--state", str(state_path)], stdout=output, stderr=output)
            time.sleep(1)
            if process.poll() is not None:
                raise RuntimeError("Benchmark endpoint failed to start")
            inside(gateway, "python3", str(Path(__file__).resolve()), "--announce", "--state", str(state_path))
            state["ready"] = True
            write_state()
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and not (control / "stop").exists():
                if process.poll() is not None:
                    raise RuntimeError("Benchmark endpoint exited early")
                time.sleep(0.5)
            state["forwarding_counters"] = json.loads(inside(gateway, "nft", "-j", "list", "table", "inet", "bench"))
            state["nat_counters"] = json.loads(inside(gateway, "nft", "-j", "list", "table", "ip", "bench_nat"))
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            for namespace in reversed(created):
                command("ip", "netns", "del", namespace)
            state["host_network_restored"] = snapshot() == baseline
            state["ready"] = False
            write_state()
        if not state["host_network_restored"]:
            raise RuntimeError("Host network differs from the baseline")
        print("BENCHMARK_CLEANUP_VERIFIED", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--server", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--announce", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--state", help=argparse.SUPPRESS)
    parser.add_argument("--control")
    parser.add_argument("--interface", default="enp0s5")
    parser.add_argument("--uplink-address")
    parser.add_argument("--client")
    parser.add_argument("--mac")
    arguments = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGHUP, lambda *_: sys.exit(129))
    if arguments.server or arguments.announce:
        if not command("ip", "netns", "identify").startswith("f4g-bench-"):
            raise RuntimeError("Endpoint requires a benchmark namespace")
        state = json.loads(Path(arguments.state).read_text())
        if arguments.announce:
            from scapy.all import ARP, Ether, get_if_hwaddr, sendp
            origin = get_if_hwaddr("uplink0")
            sendp(Ether(src=origin, dst=state["mac"]) /
                  ARP(op=2, hwsrc=origin, psrc=state["gateway"], hwdst=state["mac"], pdst=state["client"]),
                  iface="uplink0", count=2, inter=0.2, verbose=False)
        else:
            server(state)
    else:
        run(arguments)
