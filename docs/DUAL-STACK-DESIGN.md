# Dual-stack development and firmware upgrade

## Implemented on the TL-MR6400 EU V5.0

The custom OpenWrt 25.12.6 build now embeds these tools rather than depending
only on manually uploaded files:

- Bounded QMI address/session recovery and its procd service.
- Read-only `/usr/libexec/failsafe-router-doctor` JSON diagnostics, including
  per-family cellular addressing/routing, NAT6 module availability, DHCPv6
  client availability and remaining RAM/flash.
- `/usr/libexec/failsafe-cellular-ipv6-probe --run`: a temporary dual-stack
  QMI capability probe with automatic restoration of the prior network config.
- Private provisioning tooling and a SHA-256 payload manifest.
- The optional `odhcp6c` client for operators/configurations that need it.

IPv6 NAT support was already present in the kernel modules; it was not newly
invented by this update. Neither its presence nor installing a DHCPv6 client
proves that a SIM provides IPv6. LAN DHCP/RA remain off, LAN IPv6 remains off
on this backup router, and no household gateway is advertised by the new tools.

The installer recognizes a preserved provisioning marker and does not reset the
working APN, operator selection, LAN address, firewall, SSH key policy, password
or HTTPS identity. The installed payload is verified against its manifest.
The nine pre-upgrade configuration/credential hashes remain unchanged.

The first installer revision depended on an absent base64 executable. This was
found live after the first upgrade, repaired without changing network settings,
and corrected in the rebuilt/flashed image using shell printf octal decoding.
The corrected bootstrap was executed on the actual BusyBox target before the
corrected firmware upgrade. Diagnostics also avoid nounset because OpenWrt's
jshn library uses unset variables during initialization.

After the corrected upgrade, the ROM installer hash matches the built image,
all five installed tool hashes match the embedded manifest, and all nine
preserved configuration hashes still match. The marked VM path again passes
three health probes, UDP/TCP carrier-proxy DNS, verified TLS 1.3 and a 1 MiB
download in 1.25 seconds (about 6.69 Mbps including setup, not a full benchmark).
Primary fibre access also passes. Test routes/rules are removed afterward.

## Measured cellular IPv6 result

With the existing INWI roaming SIM, APN and selected French network, a temporary
IPv4v6 PDP session did not reach a usable up state during the 120-second probe.
The QMI handler repeatedly reported `Unable to connect IPv6`. No public cellular
IPv6 address/default route or verified IPv6 HTTPS success was observed.

The probe restored the original IPv4 config byte-for-byte and verified IPv4
HTTPS afterward. Its independent HUP-ignoring rollback guard restores the config
after 240 seconds if the controlling session hangs/disappears. Normal completion
restores earlier. Tests cover idempotent restoration, retry after a failed
restore and the independent guard path. The probe does not touch SIM PINs,
Freebox settings, household RAs or failover enablement.

This is a result for the tested SIM/APN/session, not proof that the modem,
every INWI service or a future French SIM cannot support IPv6. Do not permanently
enable dual-stack cellular mode until actual IPv6 traffic passes and recovery
is verified with that operator.

## Remaining architectural requirement

The existing Ethernet daemon takes over **IPv4** using ARP. Firmware on the LTE
router cannot, by itself, redirect household IPv6 traffic currently sent to the
Freebox's link-local IPv6 gateway. Do not remove the IPv6 safety interlock merely
because the backup router has IPv6-capable software.

The next implementation needs a verified routing-control design:

1. Retain working native Freebox IPv6 during normal fibre operation.
2. Control the clients' IPv6 default-router and DNS behaviour through an agreed
   gateway/delegation arrangement, verified first on an isolated test network.
3. If cellular IPv6 is actually available, validate forwarding and an explicit
   prefix/translation policy; Free's source prefixes cannot simply be reused
   unchanged through an unrelated operator.
4. If cellular is IPv4-only, withdraw unavailable IPv6 Internet routing and
   provide reachable DNS so dual-stack applications can use IPv4, while keeping
   local IPv6 intact. This cannot provide arbitrary IPv6-only Internet access;
   that would need a genuinely IPv6-capable upstream or external tunnel endpoint.
5. Test route/DNS restoration, client behaviour, failure hysteresis and rollback
   before changing household configuration or running approved failover tests.

Keep the TL-MR6400 on backup-only duty: its Ethernet ports are 100 Mbps, so routing
all Ultra fibre traffic through it would introduce a physical bottleneck. Any VM
gateway design also needs measured throughput/availability checks, not assumed
line-rate forwarding. No new tunnel service, hardware purchase, prefix
delegation change or household RA injection is authorized or deployed by this
firmware update. Automatic takeover remains monitor-only.

References: [QMI protocol handler](https://github.com/openwrt/openwrt/blob/openwrt-25.12/package/network/utils/uqmi/files/lib/netifd/proto/qmi.sh),
[TP-Link IPv6 SIM prerequisite](https://service-provider.tp-link.com/faq/198/),
[TL-MR6400 V5 specifications](https://www.tp-link.com/tr/home-networking/3g-4g-router/tl-mr6400/v5/).

## Reproducible isolated routing experiment

`tools/dual_stack_lab.py --run` is an explicitly invoked Linux/root experiment,
not an installed service or a production router-advertisement implementation.
It requires Python 3, Scapy, iproute2, nftables and ping. Run it on the Debian VM:

```sh
sudo python3 tools/dual_stack_lab.py --run
```

The lab creates two uniquely named network namespaces. Its veth pair is created
inside a namespace, never attached to the household interface or any host bridge.
It uses documentation-only addresses, has no Internet uplink, and deletes its
servers/namespaces in a finally block. Host IPv4/IPv6 route identities are checked
before and after; changing RA expiration counters are excluded from comparison.

Eight checks passed on the Debian ARM64 VM:

1. Actual Linux RA processing installs a native default route and SLAAC address.
2. A real UDP DNS query/answer succeeds before transition.
3. With two advertised routers, withdrawing the controller's own default route
   leaves the simulated Freebox default route installed.
4. Withdrawing the remaining router's own default removes Internet IPv6 routing
   while retaining the SLAAC address and working on-link IPv6 ping.
5. An off-link IPv6 connection then fails immediately with ENETUNREACH.
6. An unchanged client IPv4 DNS destination still works through backup DNAT,
   including the expected translated reply source and validated DNS answer.
7. Restoring the native advertisement and primary DNS service restores both.
8. Namespace cleanup completes and host routing remains unchanged.

The initial run exposed an overly strict comparison of expiring host RA timers;
the comparison now ignores expiration counters rather than claiming they are
static. The corrected complete run passes.

Router lifetime and DNS lifetime are independent: the lab explicitly encodes
both, including zero-lifetime RDNSS withdrawal. It does **not** test a client
resolver's RDNSS ingestion, DNS caching, Windows/Android/Apple behaviour, TCP DNS,
application Happy Eyeballs, throughput or migration of existing connections.
The IPv4 gateway is switched explicitly in this experiment; production ARP
takeover remains a separate, previously tested mechanism.

This confirms why merely adding RA withdrawal to the LTE router is insufficient:
an unrelated router cannot withdraw the Freebox's default-router identity.
The lab simulates withdrawal by each router of its **own** identity; it does not
authorize impersonating the Freebox on the household LAN. See
[RFC 4861 section 6.3.4](https://www.rfc-editor.org/rfc/rfc4861.html#section-6.3.4)
and [RFC 8106 section 5.1](https://www.rfc-editor.org/rfc/rfc8106.html#section-5.1).

### Production decision gate

The clean next pilot is a separate test LAN with one deliberately controlled
dual-stack gateway and DNS service, leaving household devices on their current
Freebox LAN. A delegated Freebox prefix, an appropriate separate network segment
and measured VM forwarding are prerequisites, not assumptions. Evaluate those
before moving any household clients. Do not route normal Ultra fibre traffic
through the MR6400's 100 Mbps ports, use competing high-priority RAs as a workaround,
or release the existing IPv6 interlock based solely on this Linux lab.

No Freebox delegation, household RA/DHCP/DNS policy or automatic takeover setting
was changed by this experiment. Those production topology changes remain a
separate approval and acceptance-test step.

After the lab, the existing marked backup path again passed three health probes,
carrier-proxy UDP/TCP DNS, verified TLS 1.3 and a 1 MiB transfer in 1.23 seconds
(about 6.83 Mbps including setup). Direct public UDP DNS remained blocked by the
roaming path as previously observed; the configured carrier proxy succeeded.
Primary HTTPS also passed, temporary routing was cleaned up, and the monitor was
restarted. The service journal had no warning/error entries during this check.

The next [Internet-connected pilot LAN](PILOT-LAN.md) has now been implemented
and exercised with a separate virtual gateway/client, real fibre IPv4/IPv6,
real cellular IPv4, stable local dual-stack DNS and restoration. It uses temporary
ULA/NAT66 for the experiment rather than changing a Freebox delegation. Its
default explicit phase switching is not production automatic outage handling.
The optional automatic pilot scenario now detects real namespace-injected socket,
DNS and HTTPS failures using independently pinned paths, debounce, backup readiness
and recovery hysteresis. It has passed live without changing household routing;
production takeover remains disabled pending real-device and topology acceptance.
