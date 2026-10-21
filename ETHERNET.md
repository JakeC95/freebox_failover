# Ethernet 4G backup — Freebox Ultra

This adaptation builds on Laurent Vivier's USB daemon. Shared authentication,
registration and legacy USB reliability have also been improved.
`freebox_ethernet.py` is the opt-in, IPv4 Ethernet implementation. The
original USB cloud-init file is **not** suitable for this deployment: do not apply
it to the existing VM or run both daemons together.

## Current installation

- Freebox: `192.168.1.254`, MAC `38:07:16:ca:d0:18`.
- Debian 12 ARM64 VM: `192.168.1.70`, interface `enp0s5`, 1 vCPU, 1 GiB RAM.
- VM disk remains on the existing USB stick. Logs are volatile; runtime status is
  in `/run/freebox-ethernet/status.json`, not on the stick.
- Application registration and its root-only token are reused. No admin password
  or token belongs in this repository.
- Ethernet mode defaults to monitoring. It changes no routes, firewall rules,
  sysctls or ARP ownership until explicitly enabled.

## Required router arrangement

Connect a **LAN** port of the 4G router to the existing Freebox LAN/switch. The
router must use its SIM/cellular connection as its upstream, not the Freebox.
Give it a unique, unused static address in `192.168.1.0/24`, outside the DHCP
pool/reservations, and set that address as `backup_gateway`. Do not assume an
address is available without checking. Disable its LAN DHCP server, IPv6 router
advertisements and any DHCPv6 server before connecting it to the production LAN.
Only the Freebox should supply normal LAN addressing. Some routers require
changing their subnet or using a different LAN port; obtain the model first.

The VM and clients keep their existing Freebox default gateway. Normal fibre
traffic never passes through the VM. During takeover, the VM uses the upstream
project's ARP gateway-impersonation approach, forwards over the **same NIC**, and
masquerades traffic to the Ethernet router. Marked routing table `4242`, rule
priority `10424` and nftables table `ip freebox_ethernet` are reserved. The VM's
ordinary default route and Freebox management access are not switched.

TCP probes to two independently hosted public IPv4 addresses use a socket mark
and the backup routing table, so successful fibre connectivity cannot make the
backup appear healthy. At least one TCP/443 connection must succeed. This is
reachability testing, not proof of DNS correctness or absence of a captive portal.
During takeover, UDP/TCP DNS requests to the Freebox IPv4 address are redirected
to the configured public DNS resolver. Other DNS configurations are unchanged.

## IPv6 limitation — must resolve before arming

This mode does **not** provide IPv6 failover, NAT66, delegated prefixes or RA
impersonation. Existing Freebox IPv6 routes can blackhole applications when fibre
fails. For a predictable IPv4-only deployment, disable IPv6 advertising on the
LAN at the Freebox, wait for/clear old client IPv6 routes, and verify the clients
before setting `lan_ipv6_disabled = true`. That setting is a human acknowledgement,
not an automatic check. Do not set it merely to bypass the interlock. The daemon
does not change the live Freebox IPv6 configuration for you.

## Installation and checks

Debian packages: `python3-requests python3-scapy iproute2 nftables libpcap0.8`.
Run `sudo bash install-freebox-ultra.sh` from the checkout. It installs code at
`/opt/freebox-failover`, preserves the live config and adds the service override
for that source location. The generic packaged unit uses `/usr/bin` scripts.
See [operations](OPERATIONS.md) for backups, diagnostics and upgrades.

```sh
sudo python3 /opt/freebox-failover/freebox_ethernet.py --check
sudo systemctl daemon-reload
sudo systemctl enable --now freebox_ethernet
sudo journalctl -u freebox_ethernet -n 30 --no-pager
sudo cat /run/freebox-ethernet/status.json
```

With `enabled = false`, the service only monitors Freebox WAN state. A `--check`
success means the API works, **not** that backup takeover is ready. Configuration
blockers are reported in the JSON. No SMS credentials are required.

Once the router is configured, connected, and the IPv6 requirement satisfied:

1. Stop `freebox_ethernet`, leave `enabled = false`, configure `backup_gateway`.
2. Run `sudo python3 /opt/freebox-failover/freebox_ethernet.py --check-backup`.
   This temporarily installs only owned policy routes, probes the backup, and
   removes those routes; it never sends takeover ARP or enables forwarding.
3. Independently test cellular Internet and DNS, check the router is not using
   fibre upstream, and verify no conflicting DHCP/RA advertisements exist.
4. Set `enabled = true`, restart the service, and arrange a controlled fibre
   disconnect while retaining local access. Test several clients, DNS, sustained
   traffic, fibre restoration, cellular loss and VM restart. Do not call the
   deployment production-ready until these physical tests pass.

## Safety and recovery

Only a continuous explicit `down`/`going_up` WAN state triggers takeover after
the configured delay, and only with a healthy backup. API/authentication errors
are `unknown`, never an outage trigger; when already active they allow a bounded
15-second grace period with a healthy backup before returning ownership to the
Freebox. Three failed backup samples release takeover. Recovery requires a continuous
`up` interval. Timing uses a monotonic clock. SIGINT/SIGTERM, exceptions and the
systemd `ExecStopPost` restore owned settings and reannounce the Freebox if needed.
Stale state is recovered before the next start. Monitor mode sends no ARP frames.

```sh
sudo systemctl disable --now freebox_ethernet
sudo python3 /opt/freebox-failover/freebox_ethernet.py --cleanup
```

Cleanup relies on the same configuration used when arming; stop/clean before
changing the primary address, MAC or interface. Do not manually delete the runtime
snapshot before cleanup. Existing unrelated firewall rules are never flushed,
and may still block forwarding; use the dedicated VM and validate its ruleset.

ARP takeover is best effort: the Freebox can still answer ARP, clients can ignore
updates, and fixed neighbour entries or switch security can prevent takeover.
Existing TCP sessions generally break across public-IP changes. Neither this
approach nor a VM hosted by the Freebox protects against a Freebox power failure,
LAN switch failure, or the Freebox itself crashing. Hardware dual-WAN routing is
needed for that stronger guarantee. No seamless/failsafe claim is made here.

Implementation references: [nftables manual](https://netfilter.org/projects/nftables/manpage.html)
and [Linux IPv4 sysctls](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html).

## Validation recorded 2026-10-21

The unchanged USB baseline was installed and smoke-tested at upstream commit
`f22a10d032d99e5244492a704412ec937304c9b1` before this adaptation. The existing
registration token works with the Ethernet monitor; the live Freebox reports `up`.

Ten logic checks passed, covering disabled defaults, invalid configuration,
authentication/MAC errors, outage and recovery delays, interrupted outage timing,
unknown API states and backup loss. An isolated Linux network namespace lab on the
VM then exercised the actual kernel routing, nftables and Scapy implementation:

- Marked probes reached the simulated backup while ordinary routes stayed intact.
- A separate client reached an HTTP server through the backup and masquerade rule.
- UDP and TCP requests to the simulated Freebox DNS address reached the backup
  resolver and returned with the expected Freebox source address.
- Full daemon operation authenticated against a simulated API, took over on a
  delayed outage, answered ARP, forwarded client traffic, and restored the gateway
  after unknown API state or sustained recovery.
- Normal cleanup restored routes, firewall and sysctls exactly; a fresh process
  recovered a saved active snapshot, and SIGTERM removed active network resources.

The lab used separate client, VM, primary and backup network namespaces; it did
not interrupt the production fibre connection. Its DNS endpoint was a transport
stub, so these checks establish translation/return routing rather than real DNS
resolution. No physical 4G router or cellular connection has been tested yet.
The running VM service is enabled at boot in monitor mode, with takeover disabled.
