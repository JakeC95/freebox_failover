#!/usr/bin/env python3
"""Exercise the actual production daemon on a disconnected virtual Ethernet LAN."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import signal
import subprocess
import sys
import tempfile
import threading
import time


def command(*arguments, required=True):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=45)
    if required and result.returncode:
        raise RuntimeError(f"{arguments[0]} failed: {result.stderr.strip()}")
    return result.stdout


def production(source, directory):
    sys.path.insert(0, str(Path(source).resolve().parent))
    specification = importlib.util.spec_from_file_location("production_under_test", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.RUNTIME = Path(directory) / "runtime"
    os.environ.pop("NOTIFY_SOCKET", None)
    return module


def worker(arguments):
    namespace = command("ip", "netns", "identify").strip()
    if not namespace.startswith("f4g-production-"):
        raise RuntimeError("Worker requires this lab's disconnected namespace")
    directory = Path(arguments.directory)
    if arguments.worker in ("daemon", "cleanup", "canary"):
        module = production(arguments.source, directory)
        settings = module.Settings(str(directory / "lab.conf"))
        if arguments.worker == "cleanup":
            module.Network(settings).cleanup()
            return
        if arguments.worker == "canary":
            client_link = json.loads(command("ip", "netns", "exec", arguments.client_namespace,
                                             "ip", "-j", "link", "show", "eth0"))[0]
            selected = (client_link["address"].lower(), "192.0.2.10")
            module.RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
            network = module.Network(settings, selected)
            network.prepare()
            try:
                network.activate()
                module.announce(settings, module.get_if_hwaddr(settings.interface), selected)
                time.sleep(0.3)
                observation = json.loads(command(
                    "ip", "netns", "exec", arguments.client_namespace, sys.executable,
                    arguments.script, "--worker", "client", "--source", arguments.source,
                    "--directory", arguments.directory))
                neighbour = command("ip", "netns", "exec", arguments.client_namespace,
                                    "ip", "neigh", "show", "192.0.2.254").strip()
                neighbour_mac = neighbour.split("lladdr ", 1)[1].split()[0]
                rules = command("nft", "list", "table", "ip", module.NFT_TABLE)
                if (observation["dns_answers"] != ["198.51.100.80"] * 2
                        or observation["upstream_saw_source"] != "192.0.2.70"
                        or neighbour_mac != module.get_if_hwaddr(settings.interface)
                        or "ip saddr 192.0.2.10" not in rules
                        or "ip saddr 192.0.2.0/24" in rules):
                    raise AssertionError({"observation": observation, "neighbour": neighbour, "rules": rules})
            finally:
                network.cleanup()
            restored = command("ip", "netns", "exec", arguments.client_namespace,
                               "ip", "neigh", "show", "192.0.2.254").strip()
            restored_mac = restored.split("lladdr ", 1)[1].split()[0]
            if restored_mac != "02:00:00:00:00:fe":
                raise AssertionError("Selected client's original Freebox ARP entry was not restored")
            print(json.dumps({"selected_client_backup_path": observation,
                              "arp_restored_to_primary": restored, "rules_scoped_to": selected}))
            return

        class SimulatedFreebox:
            last_error = None

            def __init__(self, unused):
                pass

            def state(self):
                return json.loads((directory / "state.json").read_text())["state"]

            def close(self):
                pass

        module.Freebox = SimulatedFreebox
        module.run(settings)
    elif arguments.worker == "servers":
        from scapy.all import DNS, DNSRR

        def answer(payload, address):
            request = DNS(payload)
            response_ip = "203.0.113.80" if address == "192.0.2.254" else "198.51.100.80"
            return bytes(DNS(id=request.id, qr=1, ra=1, qd=request.qd,
                             an=DNSRR(rrname=request.qd.qname, type="A", ttl=0, rdata=response_ip)))

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                payload, connection = self.request
                connection.sendto(answer(payload, self.server.server_address[0]), self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                length = int.from_bytes(self.request.recv(2), "big")
                payload = self.request.recv(length)
                response = answer(payload, self.server.server_address[0])
                self.request.sendall(len(response).to_bytes(2, "big") + response)

        class HTTP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    request = self.request.recv(1024)
                    if request:
                        body = self.client_address[0].encode()
                        self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                                             b"\r\n\r\n" + body)
                except OSError:
                    pass

        servers = []
        for address in ("192.0.2.254", "192.0.2.253"):
            servers.extend([socketserver.ThreadingUDPServer((address, 53), UDP),
                            socketserver.ThreadingTCPServer((address, 53), TCP)])
        for address in ("1.1.1.1", "9.9.9.9"):
            servers.append(socketserver.ThreadingTCPServer((address, 443), HTTP))
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print("ready", flush=True)
        while True:
            time.sleep(1)
    elif arguments.worker == "client":
        from scapy.all import DNS, DNSQR

        answers = []
        packet = bytes(DNS(id=4242, rd=1, qd=DNSQR(qname="production-lab.invalid", qtype="A")))
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            with socket.socket(socket.AF_INET, kind) as connection:
                connection.settimeout(3)
                connection.connect(("192.0.2.254", 53))
                if kind == socket.SOCK_DGRAM:
                    connection.send(packet)
                    payload = connection.recv(4096)
                else:
                    connection.sendall(len(packet).to_bytes(2, "big") + packet)
                    length = int.from_bytes(connection.recv(2), "big")
                    payload = connection.recv(length)
                response = DNS(payload)
                assert response.id == 4242 and response.qr == 1 and response.rcode == 0
                answers.append(response.an.rdata)
        with socket.create_connection(("1.1.1.1", 443), timeout=3) as connection:
            connection.sendall(b"GET / HTTP/1.0\r\n\r\n")
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        peer = b"".join(chunks).split(b"\r\n\r\n", 1)[1].decode()
        print(json.dumps({"dns_answers": answers, "upstream_saw_source": peer}))


def run(arguments):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Explicit Linux root execution is required")
    script = str(Path(__file__).resolve())
    prefix = "f4g-production-" + str(os.getpid())
    names = {role: prefix + "-" + role for role in ("switch", "upstream", "gateway", "client")}
    created, processes, passed = [], [], []

    def snapshot():
        result = {}
        for family in ("-4", "-6"):
            routes = json.loads(command("ip", "-j", family, "route", "show", "table", "all"))
            for route in routes:
                route.pop("expires", None)
            result[family] = sorted(json.dumps(route, sort_keys=True) for route in routes)
            result[family + "rules"] = command("ip", family, "rule", "show")
        result["firewall"] = command("nft", "-s", "list", "ruleset")
        return result

    baseline = snapshot()

    def inside(role, *values, required=True):
        return command("ip", "netns", "exec", names[role], *values, required=required)

    with tempfile.TemporaryDirectory(prefix=prefix + "-", dir="/run") as temporary:
        directory = Path(temporary)
        config = f"""[freebox]
token_file = /nonexistent-lab-token
lan_iface = eth0
ip = 192.0.2.254
[ethernet]
enabled = true
primary_mac = 02:00:00:00:00:fe
lan_network = 192.0.2.0/24
backup_gateway = 192.0.2.253
dns = 192.0.2.253
lan_ipv6_disabled = false
ipv6_policy = best_effort
accept_ipv6_limitations = true
probe_hosts = 1.1.1.1 9.9.9.9
standby_check = 0.3
probe_timeout = 0.2
health_rise = 2
health_fall = 3
[failover]
check = 0.2
down = 1
up = 1
garp = 0.5
unknown_grace = 1
unknown_policy = {arguments.unknown_policy}
"""
        (directory / "lab.conf").write_text(config)

        def state(value):
            pending = directory / "state.new"
            pending.write_text(json.dumps({"state": value}))
            pending.replace(directory / "state.json")

        def launch(role, action):
            log = (directory / (action + "-" + str(len(processes)) + ".log")).open("w")
            invocation = ["ip", "netns", "exec", names[role], "python3", script,
                          "--worker", action, "--source", arguments.source, "--directory", temporary]
            if action == "canary":
                invocation.extend(["--client-namespace", names["client"], "--script", script])
            process = subprocess.Popen(invocation, stdout=log, stderr=log)
            log.close()
            processes.append(process)
            return process

        def status():
            path = directory / "runtime/status.json"
            return json.loads(path.read_text()) if path.exists() else None

        def expect(active, ready=None):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = status()
                if current and current["active"] is active and (ready is None or current["backup_healthy"] is ready):
                    return current
                time.sleep(0.1)
            raise RuntimeError(f"Production state not reached: active={active}, ready={ready}")

        def client(backup):
            deadline = time.monotonic() + 8
            while True:
                observation = json.loads(inside("client", "python3", script, "--worker", "client",
                                                "--source", arguments.source, "--directory", temporary))
                observation["client_neighbours"] = inside("client", "ip", "neigh", "show")
                observation["gateway_mac"] = inside("gateway", "cat", "/sys/class/net/eth0/address").strip()
                if (observation["dns_answers"] == ["198.51.100.80" if backup else "203.0.113.80"] * 2
                        and observation["upstream_saw_source"] == ("192.0.2.70" if backup else "192.0.2.10")):
                    return
                if time.monotonic() >= deadline:
                    raise AssertionError(observation)
                time.sleep(0.2)

        def clean_resources():
            assert "freebox_ethernet" not in inside("gateway", "nft", "list", "tables")
            assert "10424:" not in inside("gateway", "ip", "-4", "rule", "show")
            assert not inside("gateway", "ip", "-4", "route", "show", "table", "4242", required=False).strip()
            assert not (directory / "runtime/network.json").exists()

        try:
            for role, name in names.items():
                command("ip", "netns", "add", name)
                created.append(name)
                inside(role, "ip", "link", "set", "lo", "up")
            inside("switch", "ip", "link", "add", "br0", "type", "bridge")
            inside("switch", "ip", "link", "set", "br0", "up")
            for role, address in (("upstream", "192.0.2.254/24"), ("gateway", "192.0.2.70/24"), ("client", "192.0.2.10/24")):
                inside("switch", "ip", "link", "add", role, "type", "veth", "peer", "name", "peer0")
                inside("switch", "ip", "link", "set", "peer0", "netns", names[role])
                inside(role, "ip", "link", "set", "peer0", "name", "eth0")
                if role == "upstream":
                    inside(role, "ip", "link", "set", "eth0", "address", "02:00:00:00:00:fe")
                inside(role, "ip", "addr", "add", address, "dev", "eth0")
                inside(role, "ip", "link", "set", "eth0", "up")
                inside("switch", "ip", "link", "set", role, "master", "br0")
                inside("switch", "ip", "link", "set", role, "up")
            for address in ("192.0.2.253/24", "1.1.1.1/32", "9.9.9.9/32"):
                inside("upstream", "ip", "addr", "add", address, "dev", "eth0")
            for role in ("gateway", "client"):
                inside(role, "ip", "route", "add", "default", "via", "192.0.2.254")
            sysctls = ("net.ipv4.conf.eth0.forwarding", "net.ipv4.conf.all.send_redirects",
                       "net.ipv4.conf.eth0.send_redirects", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.eth0.rp_filter")
            original = inside("gateway", "sysctl", *sysctls)
            capture = subprocess.Popen(["ip", "netns", "exec", names["client"], "python3", "-u", "-c",
                "from scapy.all import sniff,ARP; sniff(iface='eth0',filter='arp',store=False,prn=lambda packet: print(packet.summary(),flush=True))"],
                stdout=(directory / "arp.log").open("w"), stderr=subprocess.DEVNULL)
            processes.append(capture)
            launch("upstream", "servers")
            time.sleep(0.5)
            state("up")
            client(False)
            canary = launch("gateway", "canary")
            if canary.wait(timeout=20) != 0:
                raise RuntimeError("Selected-client production-path canary failed; see canary log")
            canary_log = json.loads((directory / f"canary-{len(processes) - 1}.log").read_text())
            if canary_log["selected_client_backup_path"]["upstream_saw_source"] != "192.0.2.70":
                raise RuntimeError("Selected-client canary did not use the backup NAT path")
            client(False)
            passed.append("selected-client unicast ARP takeover uses backup NAT, scopes IPv4 rules to /32 and restores the original ARP entry")
            daemon = launch("gateway", "daemon")
            expect(False, True)
            client(False)
            passed.append("production daemon starts without takeover and native DNS/traffic work")
            state("unknown")
            time.sleep(2)
            assert not status()["active"]
            client(False)
            passed.append("API uncertainty while on primary never initiates takeover")
            state("down")
            expect(True, True)
            time.sleep(0.4)
            client(True)
            passed.append("actual production ARP takeover, policy routing, masquerade and UDP/TCP DNS DNAT work")
            state("up")
            time.sleep(0.4)
            assert status()["active"]
            state("down")
            expect(True)
            passed.append("short primary recovery does not cause premature failback")
            state("unknown")
            time.sleep(0.4)
            assert status()["active"]
            if arguments.unknown_policy == "hold_backup":
                time.sleep(2)
                assert status()["active"] and status()["reason"] == "api_unknown_holding_backup"
                client(True)
                state("up")
                expect(False)
                client(False)
                passed.append("API uncertainty beyond grace retains working LTE; confirmed primary recovery restores native traffic")
            else:
                expect(False)
                client(False)
                passed.append("unknown API state holds briefly then releases takeover after the configured grace")
            state("down")
            expect(True)
            if arguments.unknown_policy == "hold_backup":
                state("unknown")
            inside("upstream", "nft", "add", "table", "inet", "lab_fault")
            inside("upstream", "nft", "add", "chain", "inet", "lab_fault", "input",
                   "{ type filter hook input priority -100; policy accept; }")
            inside("upstream", "nft", "add", "rule", "inet", "lab_fault", "input", "tcp", "dport", "443", "reject")
            expect(False, False)
            time.sleep(1)
            assert not status()["active"]
            passed.append("both paths unavailable releases takeover and does not oscillate")
            inside("upstream", "nft", "delete", "table", "inet", "lab_fault")
            if arguments.unknown_policy == "hold_backup":
                expect(False, True)
                assert status()["wan"] == "unknown"
                state("down")
            expect(True, True)
            client(True)
            state("up")
            expect(False)
            client(False)
            daemon.terminate()
            assert daemon.wait(timeout=10) == 0
            clean_resources()
            assert inside("gateway", "sysctl", *sysctls) == original
            passed.append("normal recovery and SIGTERM restore client routing, DNS, policy resources and sysctls")
            daemon = launch("gateway", "daemon")
            expect(False, True)
            state("down")
            expect(True)
            client(True)
            daemon.kill()
            daemon.wait(timeout=5)
            recovery_started = time.monotonic()
            inside("gateway", "python3", script, "--worker", "cleanup", "--source", arguments.source, "--directory", temporary)
            clean_resources()
            assert inside("gateway", "sysctl", *sysctls) == original
            client(False)
            passed.append("SIGKILL journal recovery explicitly restores the original gateway and network settings")
            crash_recovery_seconds = round(time.monotonic() - recovery_started, 2)
        except Exception:
            print(json.dumps({"last_status": status()}), file=sys.stderr)
            for logfile in directory.glob("*.log"):
                print(logfile.name + ":\n" + logfile.read_text()[-4000:], file=sys.stderr)
            raise
        finally:
            cleanup_errors = []
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            cleanup_errors.append(str(process.pid))
            for name in reversed(created):
                command("ip", "netns", "del", name)
            if cleanup_errors:
                raise RuntimeError("Lab processes did not exit after SIGKILL: " + ", ".join(cleanup_errors))
    if snapshot() != baseline:
        raise RuntimeError("Host routes/rules/firewall changed during disconnected lab")
    passed.append("all lab namespaces removed and host routes/rules/firewall match baseline")
    print(json.dumps({"passed": passed, "production_ready": False,
                      "source_sha256": hashlib.sha256(Path(arguments.source).read_bytes()).hexdigest(),
                      "crash_recovery_seconds": crash_recovery_seconds,
                      "scope": "disconnected virtual LAN; actual production code with simulated API and TCP/DNS servers, not real Internet/TLS"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--unknown-policy", choices=("release", "hold_backup"), default="release")
    parser.add_argument("--directory")
    parser.add_argument("--worker", choices=("daemon", "cleanup", "canary", "servers", "client"))
    parser.add_argument("--client-namespace")
    parser.add_argument("--script")
    options = parser.parse_args()
    if options.worker:
        worker(options)
    else:
        signal.signal(signal.SIGTERM, lambda *unused: sys.exit(143))
        run(options)
