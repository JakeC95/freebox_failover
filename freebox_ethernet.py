#!/usr/bin/env python3
"""Opt-in IPv4 Ethernet backup for the upstream Freebox failover project."""

import argparse
import configparser
import fcntl
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import threading
import time

from scapy.all import ARP, AsyncSniffer, Ether, get_if_hwaddr, sendp

from freebox_api import ApiError, FreeboxClient, VERSION, load_token


LOG = logging.getLogger("freebox-ethernet")
MARK = "0x4242"
TABLE = "4242"
PRIORITY = "10424"
NFT_TABLE = "freebox_ethernet"
RUNTIME = Path("/run/freebox-ethernet")


def command(*arguments, required=True, data=None):
    result = subprocess.run(arguments, input=data, text=True, capture_output=True,
                            timeout=10, check=False)
    if required and result.returncode:
        raise RuntimeError(f"{arguments[0]} failed: {result.stderr.strip()}")
    return result


def notify(message):
    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        if address.startswith("@"):
            address = "\0" + address[1:]
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
                connection.connect(address)
                connection.sendall(message.encode())
        except OSError:
            LOG.debug("Systemd notification unavailable")


def read_status():
    try:
        status = json.loads((RUNTIME / "status.json").read_text())
        age = time.monotonic() - status["updated_monotonic"]
        status["age_seconds"] = round(max(0, age), 1)
        status["stale"] = age < 0 or age > max(15, status["interval_seconds"] * 3)
        return status
    except FileNotFoundError:
        return {"mode": "stopped", "active": False, "stale": True}
    except (KeyError, TypeError, ValueError):
        return {"mode": "invalid-status", "active": False, "stale": True}


def doctor(settings):
    dependencies = {name: shutil.which(name) is not None for name in ("ip", "nft")}
    interface = Path("/sys/class/net", settings.interface).exists()
    token_error = None
    try:
        load_token(settings.token_file)
    except ApiError as error:
        token_error = error.code
    result = {"version": VERSION, "dependencies": dependencies,
              "interface_exists": interface, "token_error": token_error,
              "blockers": settings.blockers(), "service": read_status()}
    if dependencies["ip"] and interface:
        result["addresses"] = json.loads(command("ip", "-j", "addr", "show", "dev", settings.interface).stdout)
        result["default_routes"] = json.loads(command("ip", "-j", "-4", "route", "show", "default").stdout)
    result["monitor_ready"] = all(dependencies.values()) and interface and token_error is None
    return result


def owned_table_exists():
    ruleset = json.loads(command("nft", "-j", "list", "tables").stdout)
    return any(entry.get("table", {}).get("family") == "ip"
               and entry.get("table", {}).get("name") == NFT_TABLE
               for entry in ruleset.get("nftables", []))


class Settings:
    def __init__(self, filename):
        config = configparser.ConfigParser(interpolation=None)
        if not config.read(filename):
            raise ValueError(f"Cannot read configuration: {filename}")
        self.interface = config.get("freebox", "lan_iface")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", self.interface):
            raise ValueError("Invalid LAN interface")
        self.primary = str(ipaddress.IPv4Address(config.get("freebox", "ip")))
        self.token_file = config.get("freebox", "token_file")
        self.mac = config.get("ethernet", "primary_mac").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", self.mac):
            raise ValueError("A verified primary_mac is required for emergency restoration")
        self.network = ipaddress.IPv4Network(config.get("ethernet", "lan_network"))
        self.backup = config.get("ethernet", "backup_gateway", fallback="").strip()
        if self.backup:
            self.backup = str(ipaddress.IPv4Address(self.backup))
            if self.backup == self.primary or ipaddress.ip_address(self.backup) not in self.network:
                raise ValueError("Backup gateway must be a distinct address on the LAN")
            if ipaddress.ip_address(self.backup) in (self.network.network_address,
                                                    self.network.broadcast_address):
                raise ValueError("Backup gateway cannot be a network/broadcast address")
        if ipaddress.ip_address(self.primary) not in self.network:
            raise ValueError("Primary gateway must belong to lan_network")
        self.enabled = config.getboolean("ethernet", "enabled", fallback=False)
        self.ipv6_disabled = config.getboolean("ethernet", "lan_ipv6_disabled", fallback=False)
        self.dns = str(ipaddress.IPv4Address(config.get("ethernet", "dns", fallback="1.1.1.1")))
        self.probes = config.get("ethernet", "probe_hosts", fallback="1.1.1.1 9.9.9.9").split()
        if len(set(self.probes)) < 2:
            raise ValueError("Configure at least two distinct public IPv4 probe hosts")
        for host in self.probes + [self.dns]:
            if not ipaddress.IPv4Address(host).is_global:
                raise ValueError("Probe and DNS addresses must be public IPv4 addresses")
        self.period = config.getfloat("failover", "check", fallback=2)
        self.down = config.getfloat("failover", "down", fallback=10)
        self.up = config.getfloat("failover", "up", fallback=20)
        self.garp = config.getfloat("failover", "garp", fallback=3)
        self.unknown_grace = config.getfloat("failover", "unknown_grace", fallback=15)
        self.backup_check = config.getfloat("ethernet", "standby_check", fallback=15)
        self.probe_timeout = config.getfloat("ethernet", "probe_timeout", fallback=1)
        self.backup_rise = config.getint("ethernet", "health_rise", fallback=2)
        self.backup_fall = config.getint("ethernet", "health_fall", fallback=3)
        if any(not math.isfinite(value) or value <= 0
               for value in (self.period, self.down, self.up, self.garp,
                             self.unknown_grace, self.backup_check, self.probe_timeout)):
            raise ValueError("All timing values must be finite and positive")
        if self.period > 30 or self.probe_timeout > 3 or len(self.probes) > 4:
            raise ValueError("check must be <=30 seconds; probes <=4 hosts with <=3 second timeout")
        if not 1 <= self.backup_rise <= 10 or not 1 <= self.backup_fall <= 10:
            raise ValueError("health_rise and health_fall must be between 1 and 10")

    def blockers(self):
        return (["backup_gateway is not configured"] if not self.backup else []) + (
            [] if self.ipv6_disabled else ["LAN IPv6 must be disabled and acknowledged before IPv4 takeover"])


class Freebox(FreeboxClient):
    def __init__(self, settings):
        self.settings = settings
        super().__init__(settings.primary, settings.token_file, settings.mac)


class BackupHealth:
    def __init__(self, settings):
        self.settings = settings
        self.ready = False
        self.successes = 0
        self.failures = 0

    def update(self, reachable):
        if reachable:
            self.successes += 1
            self.failures = 0
            if self.successes >= self.settings.backup_rise:
                self.ready = True
        else:
            self.failures += 1
            self.successes = 0
            if self.failures >= self.settings.backup_fall:
                self.ready = False
        return self.ready


class Decision:
    def __init__(self, settings):
        self.settings = settings
        self.since = None
        self.previous = None
        self.reason = "starting"

    def update(self, state, healthy, active, now):
        category = "up" if state == "up" else "down" if state in ("down", "going_up", "going_down") else "unknown"
        if category != self.previous:
            self.since = now
            self.previous = category
        if active and not healthy:
            self.reason = "backup_unavailable"
            return False
        if category == "unknown":
            holding = active and healthy and now - self.since < self.settings.unknown_grace
            self.reason = "api_unknown_grace" if holding else "api_unknown"
            return holding
        if category == "up" and now - self.since >= self.settings.up:
            self.reason = "primary_up"
            return False
        if category == "down" and now - self.since >= self.settings.down and healthy:
            self.reason = "primary_down_backup_ready"
            return True
        self.reason = "waiting_primary_recovery" if active else (
            "backup_unavailable" if category == "down" and not healthy else "waiting_primary_" + category)
        return active


def announce(settings, mac):
    packet = Ether(src=get_if_hwaddr(settings.interface), dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=settings.primary, pdst=settings.primary,
        hwsrc=mac, hwdst="ff:ff:ff:ff:ff:ff")
    sendp(packet, iface=settings.interface, count=3, inter=0.1, verbose=False)


class Network:
    def __init__(self, settings):
        self.settings = settings
        self.state_file = RUNTIME / "network.json"
        self.snapshot = None
        self.active = False
        self.last_probe = None

    def save(self):
        temporary = self.state_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.snapshot))
        temporary.chmod(0o600)
        temporary.replace(self.state_file)

    def prepare(self):
        settings = self.settings
        addresses = json.loads(command("ip", "-j", "-4", "addr", "show", "dev", settings.interface).stdout)
        local = [entry["local"] for device in addresses for entry in device["addr_info"]]
        if settings.backup in local or settings.primary in local:
            raise ValueError("Gateway address is assigned to the VM")
        if not any(ipaddress.ip_address(address) in settings.network for address in local):
            raise ValueError("VM does not have an address on lan_network")
        if owned_table_exists():
            raise ValueError("Reserved nftables table is already in use")
        rules = json.loads(command("ip", "-j", "-4", "rule", "show").stdout)
        if any(str(rule.get("priority")) == PRIORITY or str(rule.get("table")) == TABLE
               or str(rule.get("fwmark")) in (MARK, str(int(MARK, 16))) for rule in rules):
            raise ValueError("Reserved policy routing resources are already in use")
        routes = command("ip", "-4", "route", "show", "table", TABLE, required=False)
        if routes.stdout.strip():
            raise ValueError("Reserved routing table is already in use")
        self.snapshot = {"sysctls": {}, "active": False,
                         "interface": settings.interface, "primary": settings.primary,
                         "mac": settings.mac}
        self.save()
        command("ip", "-4", "route", "add", str(settings.network), "dev", settings.interface, "table", TABLE)
        command("ip", "-4", "route", "add", "default", "via", settings.backup,
                "dev", settings.interface, "table", TABLE)
        command("ip", "-4", "rule", "add", "priority", PRIORITY, "fwmark", MARK, "table", TABLE)

    def healthy(self):
        for host in self.settings.probes:
            started = time.monotonic()
            try:
                routes = json.loads(command("ip", "-j", "-4", "route", "get", host, "mark", MARK).stdout)
                if not routes or routes[0].get("gateway") != self.settings.backup or routes[0].get("dev") != self.settings.interface:
                    self.last_probe = {"reachable": False, "error": "backup_route_mismatch"}
                    return False
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                self.last_probe = {"reachable": False, "error": "backup_route_unavailable"}
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(MARK, 16))
                    connection.settimeout(self.settings.probe_timeout)
                    connection.connect((host, 443))
                    self.last_probe = {"host": host, "reachable": True,
                                       "latency_ms": round((time.monotonic() - started) * 1000, 2)}
                    return True
            except OSError:
                continue
        self.last_probe = {"reachable": False}
        return False

    def activate(self):
        settings = self.settings
        for name, value in {
            f"net/ipv4/conf/{settings.interface}/forwarding": "1",
            "net/ipv4/conf/all/send_redirects": "0",
            f"net/ipv4/conf/{settings.interface}/send_redirects": "0",
            "net/ipv4/conf/all/rp_filter": "2",
            f"net/ipv4/conf/{settings.interface}/rp_filter": "2",
        }.items():
            path = Path("/proc/sys") / name
            self.snapshot["sysctls"][name] = path.read_text().strip()
            self.save()
            path.write_text(value)
        rules = f'''table ip {NFT_TABLE} {{
 chain route_mark {{ type filter hook prerouting priority mangle; policy accept;
  iifname "{settings.interface}" ip saddr {settings.network} ip daddr != {settings.network} meta mark set {MARK}
  iifname "{settings.interface}" ip saddr {settings.network} ip daddr {settings.primary} meta l4proto {{ tcp, udp }} th dport 53 meta mark set {MARK}
 }}
 chain dns_redirect {{ type nat hook prerouting priority dstnat; policy accept;
  meta mark {MARK} ip daddr {settings.primary} meta l4proto {{ tcp, udp }} th dport 53 dnat to {settings.dns}
 }}
 chain source_nat {{ type nat hook postrouting priority srcnat; policy accept;
  oifname "{settings.interface}" meta mark {MARK} masquerade
 }}
}}'''
        command("nft", "-c", "-f", "-", data=rules)
        self.snapshot["active"] = True
        self.save()
        command("nft", "-f", "-", data=rules)
        self.active = True

    def deactivate(self):
        self.active = False
        errors = []
        try:
            if owned_table_exists():
                command("nft", "delete", "table", "ip", NFT_TABLE)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(f"Firewall restoration failed: {error}")
        if self.snapshot and self.snapshot["active"]:
            try:
                announce(self.settings, self.settings.mac)
            except Exception as error:
                errors.append(f"Gateway restoration announcement failed: {error}")
        if self.snapshot:
            for name, value in self.snapshot["sysctls"].items():
                try:
                    (Path("/proc/sys") / name).write_text(value)
                except OSError as error:
                    errors.append(f"Sysctl restoration failed: {error}")
            if errors:
                raise RuntimeError("; ".join(errors))
            self.snapshot["sysctls"] = {}
            self.snapshot["active"] = False
            self.save()

    def cleanup(self):
        if not self.snapshot and self.state_file.exists():
            self.snapshot = json.loads(self.state_file.read_text())
            if any(self.snapshot[key] != getattr(self.settings, key)
                   for key in ("interface", "primary", "mac")):
                raise ValueError("Recover using the configuration that created network.json")
        if self.snapshot:
            try:
                self.deactivate()
            finally:
                command("ip", "-4", "rule", "del", "priority", PRIORITY,
                        "fwmark", MARK, "table", TABLE, required=False)
                command("ip", "-4", "route", "flush", "table", TABLE)
            self.state_file.unlink(missing_ok=True)
            self.snapshot = None


def run(settings, monitor_only=False, check_backup=False):
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    armed = settings.enabled and not monitor_only
    if armed and settings.blockers():
        raise ValueError("; ".join(settings.blockers()))
    if check_backup and not settings.backup:
        raise ValueError("backup_gateway is not configured")
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (RUNTIME / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        network = Network(settings)
        network.cleanup()
        sniffer = None
        api = None
        try:
            if armed or check_backup:
                network.prepare()
            if check_backup:
                healthy = network.healthy()
                print(json.dumps({"backup_reachable_via_policy_route": healthy}))
                return 0 if healthy else 1
            api = Freebox(settings)
            decision = Decision(settings)
            backup_health = BackupHealth(settings)
            mac = get_if_hwaddr(settings.interface) if armed else None

            def handle(packet):
                if (network.active and ARP in packet and packet[ARP].op == 1
                        and packet[ARP].pdst == settings.primary and packet[ARP].hwsrc != mac
                        and packet[ARP].psrc not in (settings.primary, settings.backup)):
                    sendp(Ether(src=mac, dst=packet[ARP].hwsrc) / ARP(
                        op=2, psrc=settings.primary, hwsrc=mac,
                        pdst=packet[ARP].psrc, hwdst=packet[ARP].hwsrc),
                        iface=settings.interface, verbose=False)

            if armed:
                ready = threading.Event()
                sniffer = AsyncSniffer(iface=settings.interface, filter="arp", prn=handle,
                                       store=False, started_callback=ready.set)
                sniffer.start()
                if not ready.wait(5):
                    raise RuntimeError("ARP responder could not start")
            LOG.info("Started in %s mode", "ARMED IPv4 Ethernet" if armed else "MONITOR-ONLY (no takeover)")
            started = time.monotonic()
            first_report = True
            last_state = None
            last_error = None
            last_announcement = 0
            next_probe = 0
            while not stop.is_set():
                cycle_started = time.monotonic()
                state = api.state()
                if stop.is_set():
                    break
                if state != last_state:
                    LOG.info("Freebox WAN: %s", state)
                    last_state = state
                if api.last_error != last_error:
                    if api.last_error:
                        LOG.warning("Freebox API: %s", api.last_error)
                    last_error = api.last_error
                now = time.monotonic()
                probe_interval = settings.backup_check if state == "up" and not network.active else settings.period
                if armed and (now >= next_probe or now + probe_interval < next_probe):
                    previously_ready = backup_health.ready
                    backup_health.update(network.healthy())
                    next_probe = time.monotonic() + probe_interval
                    if backup_health.ready != previously_ready:
                        LOG.info("Backup readiness: %s", backup_health.ready)
                healthy = backup_health.ready
                if stop.is_set():
                    break
                if sniffer is not None and not sniffer.running:
                    raise RuntimeError("ARP responder stopped")
                now = time.monotonic()
                desired = decision.update(state, healthy, network.active, now) if armed else False
                if desired and not network.active:
                    network.activate()
                    LOG.warning("Backup takeover activated: %s", decision.reason)
                elif not desired and network.active:
                    network.deactivate()
                    LOG.warning("Returned gateway ownership to Freebox: %s", decision.reason)
                if network.active and now - last_announcement >= settings.garp:
                    announce(settings, mac)
                    last_announcement = now
                status = {"version": VERSION, "pid": os.getpid(),
                          "mode": "armed" if armed else "monitor-only", "wan": state,
                          "active": network.active, "backup_healthy": healthy if armed else None,
                          "backup_probe": network.last_probe,
                          "reason": decision.reason if armed else "takeover_disabled",
                          "api_error": api.last_error,
                          "uptime_seconds": round(now - started, 1),
                          "interval_seconds": settings.period, "updated_monotonic": time.monotonic(),
                          "blockers": settings.blockers(), "updated": time.time()}
                temporary = RUNTIME / "status.tmp"
                temporary.write_text(json.dumps(status) + "\n")
                temporary.replace(RUNTIME / "status.json")
                if first_report:
                    notify("READY=1")
                    first_report = False
                notify("WATCHDOG=1\nSTATUS=" + status["mode"] + ": WAN " + state + ", " + status["reason"])
                stop.wait(max(0, settings.period - (time.monotonic() - cycle_started)))
        finally:
            try:
                notify("STOPPING=1\nSTATUS=Restoring gateway ownership")
                network.cleanup()
            finally:
                if sniffer is not None and sniffer.running:
                    sniffer.stop()
                (RUNTIME / "status.json").unlink(missing_ok=True)
                if api is not None:
                    api.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="/etc/freebox_ethernet.conf")
    parser.add_argument("--version", action="version", version=VERSION)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--monitor-only", action="store_true")
    modes.add_argument("--check", action="store_true", help="Read-only configuration and Freebox API check")
    modes.add_argument("--check-backup", action="store_true", help="Temporary marked probe routes; never takes over")
    modes.add_argument("--cleanup", action="store_true", help="Recover owned network resources after a crash")
    modes.add_argument("--status", action="store_true", help="Show runtime status and detect stale monitoring")
    modes.add_argument("--doctor", action="store_true", help="Read-only dependency, token and network diagnostics")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.status:
            status = read_status()
            print(json.dumps(status))
            return 1 if status["stale"] else 0
        settings = Settings(args.config)
        if args.doctor:
            result = doctor(settings)
            print(json.dumps(result))
            return 0 if result["monitor_ready"] else 1
        if args.check:
            api = Freebox(settings)
            try:
                state = api.state()
                print(json.dumps({"wan": state, "api_error": api.last_error,
                                  "enabled": settings.enabled, "blockers": settings.blockers()}))
            finally:
                api.close()
            return 0 if state != "unknown" else 1
        if os.geteuid() != 0:
            raise ValueError("Run as root for networking or protected runtime state")
        if args.cleanup:
            RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (RUNTIME / "lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                Network(settings).cleanup()
                (RUNTIME / "status.json").unlink(missing_ok=True)
            return 0
        return run(settings, args.monitor_only, args.check_backup)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, configparser.Error) as error:
        LOG.error("%s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
