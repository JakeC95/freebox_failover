#!/usr/bin/env python3
"""Opt-in, isolated Linux namespace experiment; never a household RA sender."""

import argparse
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def command(*arguments, required=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=15)
    if required and result.returncode:
        raise RuntimeError(f"{arguments!r}: {result.stderr.strip()}")
    return result.stdout


def worker(action, values):
    namespace = command("ip", "netns", "identify").strip()
    if not namespace.startswith("f4g-v6lab-"):
        raise RuntimeError("Worker must run inside this lab's network namespace")
    from scapy.all import DNS, DNSQR, DNSRR, Ether, IPv6, ICMPv6ND_RA
    from scapy.all import ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, sendp

    if action == "advertise":
        source, lifetime, dns_lifetime = values
        packet = (Ether(dst="33:33:00:00:00:01") /
                  IPv6(src=source, dst="ff02::1", hlim=255) /
                  ICMPv6ND_RA(routerlifetime=int(lifetime)) /
                  ICMPv6NDOptPrefixInfo(prefix="2001:db8:42::", prefixlen=64,
                                       validlifetime=3600, preferredlifetime=1800) /
                  ICMPv6NDOptRDNSS(lifetime=int(dns_lifetime),
                                  dns=["2001:db8:42::53"]))
        decoded = Ether(bytes(packet))
        assert decoded[ICMPv6ND_RA].routerlifetime == int(lifetime)
        assert decoded[ICMPv6NDOptRDNSS].lifetime == int(dns_lifetime)
        sendp(packet, iface="eth0", count=3, inter=0.1, verbose=False)
    elif action == "dns-server":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind((values[0], 53))
            print("ready", flush=True)
            while True:
                data, peer = connection.recvfrom(4096)
                query = DNS(data)
                answer = DNS(id=query.id, qr=1, aa=1, qd=query.qd,
                             an=DNSRR(rrname=query.qd.qname, type="A",
                                      ttl=0, rdata="192.0.2.80"))
                connection.sendto(bytes(answer), peer)
    elif action == "dns-query":
        query = DNS(id=4242, rd=1, qd=DNSQR(qname="lab.invalid", qtype="A"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.sendto(bytes(query), ("192.0.2.254", 53))
            data, peer = connection.recvfrom(4096)
        answer = DNS(data)
        assert peer == ("192.0.2.254", 53)
        assert answer.id == 4242 and answer.qr == 1
        assert answer.an.rdata == "192.0.2.80"
    elif action == "ipv6-unreachable":
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            try:
                connection.connect(("2001:db8:ffff::1", 443))
            except OSError as error:
                assert error.errno == errno.ENETUNREACH, error
            else:
                raise AssertionError("Unexpected IPv6 Internet route")


def run_lab():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run explicitly as root on Linux with iproute2, nftables and Scapy")
    script = str(Path(__file__).resolve())
    prefix = f"f4g-v6lab-{os.getpid()}"
    router, client = prefix + "-r", prefix + "-c"
    created = []
    servers = []
    passed = []
    def host_routes(family):
        routes = json.loads(command("ip", "-j", family, "route", "show", "table", "all"))
        for route in routes:
            route.pop("expires", None)
        return sorted(json.dumps(route, sort_keys=True) for route in routes)

    original_routes = {family: host_routes(family) for family in ("-4", "-6")}

    def inside(namespace, *arguments):
        return command("ip", "netns", "exec", namespace, *arguments)

    def advertise(source, lifetime, dns_lifetime=600):
        inside(router, "python3", script, "--worker", "advertise", source,
               str(lifetime), str(dns_lifetime))

    def defaults():
        return {entry.get("gateway") for entry in json.loads(
            inside(client, "ip", "-j", "-6", "route", "show", "default"))}

    def expect_routes(expected):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if defaults() == expected:
                return
            time.sleep(0.1)
        raise AssertionError(f"Expected routers {expected}, got {defaults()}")

    def start_dns(address):
        process = subprocess.Popen(["ip", "netns", "exec", router, "python3",
                                    script, "--worker", "dns-server", address],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        servers.append(process)
        time.sleep(0.5)
        if process.poll() is not None:
            raise RuntimeError(process.communicate()[1])
        return process

    try:
        for namespace in (router, client):
            command("ip", "netns", "add", namespace)
            created.append(namespace)
            inside(namespace, "ip", "link", "set", "lo", "up")
        inside(router, "ip", "link", "add", "eth0", "type", "veth",
               "peer", "name", "peer0")
        inside(router, "ip", "link", "set", "peer0", "netns", client)
        inside(client, "ip", "link", "set", "peer0", "name", "eth0")
        for namespace in (router, client):
            inside(namespace, "sysctl", "-qw", "net.ipv6.conf.eth0.disable_ipv6=0",
                   "net.ipv6.conf.eth0.accept_dad=0")
            inside(namespace, "ip", "link", "set", "eth0", "up")
        inside(client, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=0",
               "net.ipv6.conf.eth0.accept_ra=1", "net.ipv6.conf.eth0.autoconf=1")
        for address in ("fe80::254/64", "fe80::253/64", "2001:db8:42::53/64"):
            inside(router, "ip", "-6", "addr", "add", address, "dev", "eth0")
        for address in ("192.0.2.254/24", "192.0.2.253/24"):
            inside(router, "ip", "addr", "add", address, "dev", "eth0")
        inside(client, "ip", "addr", "add", "192.0.2.10/24", "dev", "eth0")
        inside(client, "ip", "route", "add", "default", "via", "192.0.2.254")
        advertise("fe80::254", 1800)
        expect_routes({"fe80::254"})
        addresses = json.loads(inside(client, "ip", "-j", "-6", "addr", "show", "dev", "eth0"))
        slaac = {entry["local"] for interface in addresses for entry in interface["addr_info"]
                 if entry["local"].startswith("2001:db8:42:")}
        assert slaac, "Client did not obtain a SLAAC address"
        passed.append("native default router and SLAAC installed by real Linux RA processing")
        primary_dns = start_dns("192.0.2.254")
        inside(client, "python3", script, "--worker", "dns-query")
        passed.append("IPv4 DNS response validated before transition")
        advertise("fe80::253", 1800)
        expect_routes({"fe80::254", "fe80::253"})
        advertise("fe80::253", 0, 0)
        expect_routes({"fe80::254"})
        passed.append("controller withdrawal does not remove the competing Freebox router")
        advertise("fe80::254", 0, 0)
        expect_routes(set())
        remaining = inside(client, "ip", "-j", "-6", "addr", "show", "dev", "eth0")
        assert all(address in remaining for address in slaac)
        inside(client, "ping", "-6", "-c", "1", "-W", "2", "2001:db8:42::53")
        passed.append("owned-router withdrawal removes IPv6 default but preserves local IPv6")
        inside(client, "python3", script, "--worker", "ipv6-unreachable")
        passed.append("off-link IPv6 fails immediately with ENETUNREACH instead of timing out")
        primary_dns.terminate()
        primary_dns.wait(timeout=5)
        backup_dns = start_dns("192.0.2.253")
        inside(router, "nft", "add", "table", "ip", "lab_dns")
        inside(router, "nft", "add", "chain", "ip", "lab_dns", "prerouting",
               "{ type nat hook prerouting priority dstnat; policy accept; }")
        inside(router, "nft", "add", "rule", "ip", "lab_dns", "prerouting",
               "ip", "daddr", "192.0.2.254", "udp", "dport", "53", "dnat", "to", "192.0.2.253")
        inside(client, "ip", "route", "replace", "default", "via", "192.0.2.253")
        inside(client, "python3", script, "--worker", "dns-query")
        passed.append("unchanged client IPv4 DNS destination works through backup DNAT")
        inside(router, "nft", "delete", "table", "ip", "lab_dns")
        backup_dns.terminate()
        backup_dns.wait(timeout=5)
        start_dns("192.0.2.254")
        inside(client, "ip", "route", "replace", "default", "via", "192.0.2.254")
        advertise("fe80::254", 1800)
        expect_routes({"fe80::254"})
        inside(client, "python3", script, "--worker", "dns-query")
        passed.append("primary IPv6 router and IPv4 DNS restored")
    finally:
        for process in servers:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        for namespace in reversed(created):
            command("ip", "netns", "del", namespace)
    assert all(host_routes(family) == routes for family, routes in original_routes.items())
    passed.append("namespaces removed and host IPv4/IPv6 route tables unchanged")
    print(json.dumps({"passed": passed, "production_ready": False,
                      "limitations": ["Linux client only", "no client resolver RDNSS ingestion test",
                                      "no Internet throughput or existing-session migration test",
                                      "no household gateway control deployed"]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--run", action="store_true")
    choice.add_argument("--worker", choices=("advertise", "dns-server", "dns-query", "ipv6-unreachable"),
                        help=argparse.SUPPRESS)
    parser.add_argument("values", nargs="*")
    arguments = parser.parse_args()
    if arguments.run:
        run_lab()
    else:
        worker(arguments.worker, arguments.values)
