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
