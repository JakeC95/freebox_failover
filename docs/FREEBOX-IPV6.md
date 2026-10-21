# Freebox Ultra IPv6 audit

Read-only audit on 2026-10-22 local time, Freebox OS **4.13.1**, Ultra board
`fbxgw9r`. No Freebox/router/client network settings were changed, no outage
was induced, and automatic takeover remains disabled.

## Controls actually exposed

The installed `Fbx.os.app.settings.ConnectionIpv6Config` UI and authenticated
configuration API expose:

- IPv6 firewall and protection of delegated prefixes.
- DHCPv6 enablement and custom IPv6 DNS servers.
- Eight prefix-delegation entries with configurable next hops.
- A displayed link-local router address.

The live IPv6 status is enabled, the main IPv6 firewall is enabled, DHCPv6 is
disabled, custom IPv6 DNS is disabled, and all delegation next hops are empty.
No simple IPv6-disable or RA-disable control is present in the audited UI.
The API reports `ipv6_enabled`, but no write was attempted: a legacy field is
not evidence that a supported off switch exists.

Freebox's own engineering response explains why disabling the box's native
IPv6 transport is not supported. That is distinct from designing a separate
client LAN whose addressing/routing is controlled by another gateway. Do not
confuse disabling DHCPv6 with disabling SLAAC/router advertisements, and do not
treat a deliberately nonexistent delegation next hop as a harmless off switch.

## Observation limits

Freebox LAN records identify IPv4/IPv6 addresses, active/reachable flags and
activity timestamps. An assigned or active public IPv6 address demonstrates
IPv6 capability/activity, not that every application uses or requires it.
Link-local addresses alone do not demonstrate IPv6 Internet access. Historical
records must not be counted as currently connected devices.

An established TCP connection from a public IPv6 source to a public IPv6
destination on the PC confirms actual IPv6 application use there. A verified
IPv6 HTTPS request from the Linux VM also succeeds. Neither observation proves
what applications on another switched-LAN device are doing. No browsing
payloads were captured and no other device was logged into or reconfigured.

Device names, MAC/IP addresses, inventory snapshots and application-connection
counts are retained only in a restricted local audit directory, not this public
repository. No currently active IPv6-only host was identified in the snapshot;
that does not rule out sleeping/offline equipment or IPv6-only remote services.

## Consequence for this project

The marked VM IPv4 path through the OpenWrt LTE router passes DNS, verified
HTTPS and a 1 MiB download, while ordinary fibre egress remains separate.
Temporary test routes/rules are removed and the monitor-only service restored.
This does not provide IPv6 failover or prove a complete household switchover.

Preserve the existing working IPv6 configuration while deciding how both
address families should behave during an outage. Options require explicit
design and testing: a verified IPv4-only client LAN, or a gateway that controls
both IPv4 and IPv6 and handles the backup's actual capabilities. IPv6 prefixes
from Free cannot simply be forwarded through an unrelated cellular provider.
Do not disable IPv6 on individual devices, weaken the firewall, change Freebox
delegations or set `lan_ipv6_disabled=true` merely to satisfy the interlock.

Sources: [Freebox engineering response, FS#39666](https://dev.freebox.fr/bugs/task/39666),
[Freebox LAN API record semantics](https://dev.freebox.fr/sdk/os/lan/),
[IETF dual-stack connection fallback](https://www.rfc-editor.org/rfc/rfc8305.html).
