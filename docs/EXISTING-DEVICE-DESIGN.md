# Existing-device failover direction

## Owner constraints

- Decision-making should live on the existing Freebox/its VM and the OpenWrt
  cellular router where possible, not an additional always-on gateway.
- The Windows computer remains a temporary test client, not infrastructure.
- Preserve the two working bridged APs, their roaming and unmanaged PoE switch.
- Preparation alone never authorizes household changes. The owner has approved
  this maintenance window; the Ethernet service is armed, with no AP, DHCP,
  IPv6-advertisement or wiring changes.

The separately routed gateway/LAN candidate is therefore not the active rollout
plan. Its exploration and benchmark are retained as evidence, not as a hardware
requirement imposed on the owner.

## Target control/data-plane separation

The Freebox continues routing native fibre IPv4/IPv6 directly during normal
operation. The VM observes primary/cellular health and runs bounded decision,
recovery and diagnostic logic. The LTE router manages its modem/session and
provides the alternate IPv4 egress. Neither AP is turned into a household router
or required to participate in the failover decision.

The existing Ethernet service already implements opt-in IPv4 gateway ARP
takeover with marked routing to the cellular router, DNS redirection, health
guards and restoration. Keeping that mechanism failover-only avoids making VM
throughput or its USB storage a normal fibre-path bottleneck. The installed
service is armed but currently idle on fibre; the physical fibre-outage and
whole-household LTE path remain untested.

This describes the intended separation, **not a fully validated dual-stack
production design**. Do not disable LAN IPv6 to bypass the interlock.

## Explicit best-effort IPv6 policy

The owner accepts IPv4-only backup as a practical fallback, rather than requiring
perfect IPv6 continuity. Selected Android tests with the deployment SIM passed
application use and native IPv6 restoration without reconnecting Wi-Fi. This
does not establish compatibility for every application: selected Windows .NET
transports have failed deadlines under silent IPv6 loss.

The candidate source provides an explicit `ipv6_policy=best_effort` option with
`accept_ipv6_limitations=true`. It does not disable IPv6, provide IPv6 takeover,
or guarantee application fallback. Defaults retain `require_disabled`; the
installed service explicitly uses the acknowledged `best_effort` policy. See the
[production qualification notes](PRODUCTION-QUALIFICATION.md) before deployment.

Clients currently learn the Freebox's link-local IPv6 default router. With the
tested IPv4-only SIM, merely redirecting IPv4 cannot make their existing IPv6
Internet path usable over LTE. Withdrawing a VM's own RA does not withdraw the
Freebox's identity. Successful one-client high-preference probes do not justify
competing household RAs, address impersonation or blanket AP bridge filtering.

A fresh authenticated read of the installed Freebox IPv6 configuration reports
IPv6 enabled, eight delegation entries and no assigned next hops. Returned
fields cover enablement, firewall policy, link-local identity and delegations;
there is no separate RA-control field in that returned configuration. This is
not proof that no other supported control exists. It is also not permission to
write a supposedly harmless value to a global setting to test its effect.

Preparation must establish whether the installed Freebox offers a supported,
rollback-safe way to control unavailable IPv6 routing/DNS while keeping normal
native IPv6 and the APs unchanged. If not, present that conflict and practical
limitations to the owner. Do not claim complete failsafe behaviour by relying
only on some applications eventually falling back from black-holed IPv6, or
quietly disable IPv6 across clients to satisfy the existing daemon's interlock.

No changes to Freebox prefix delegation, IPv6 enablement/firewall, DHCP, APs or
household advertisements were made by this evaluation.

The completed [selected-client application fallback test](APPLICATION-FALLBACK.md)
distinguishes silent IPv6 loss from immediate rejection across multiple Windows
HTTP stacks. Compatibility results bound the accepted best-effort policy; they
do not prove complete IPv6 or IPv6-DNS failover.

## Fault coverage boundaries

This can target an ISP/fibre-service outage while the Freebox, its LAN switching,
the VM and the LTE router remain powered and operational. A VM hosted on the
Freebox cannot provide independent control through a complete Freebox failure.
The same switch/LAN topology may also depend on the Freebox remaining alive.
Do not advertise power/Freebox-hardware failure protection without an independent
path, power design and additional evidence.

The monitor-only service restart and process-crash recovery, selected-client
production ARP/LTE/failback path, deployment-SIM DNS/HTTPS checks, and Android/TV
application rehearsals have passed. Still unqualified are VM/Freebox/USB loss
during active failover, full-household rollback, other household applications,
and performance beyond the measured 1 GbE test path. Normal fibre operation must
not depend on the Windows test computer staying on. See
[rollout gates](ROLLOUT-PLAN.md) and [local benchmark](GATEWAY-BENCHMARK.md).
