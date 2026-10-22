# Selected-client local gateway benchmark

This is a bounded preparation tool, not a production gateway. It measures an
actual Windows client through the VM's Ethernet path, namespace forwarding,
conntrack and source NAT to a private in-VM endpoint. It does not use Internet
bandwidth, cellular data or either household AP as a test client.

## Confinement and rollback

`tools/gateway_benchmark.py --run` requires explicit Linux/root execution, a
checked unused uplink address, one client IPv4/MAC pair and a new private
`/run/failsafe4g-benchmark-*` control directory. It shares the dual-stack pilot's
exclusive lock, probes for uplink address conflicts, and creates only uniquely
named `f4g-bench-*` namespaces. No host route/firewall/sysctl is changed.

The gateway has connected routes only: **no Internet default route**. Its input
policy drops traffic; forwarding allows only the selected client IP/MAC to
`198.18.71.2:5201` and established replies back. Source NAT is confined to that
one flow destination in the namespace. The HTTP endpoint accepts only the
translated source, a per-run random URL token and bounded 128 MiB transfers.
It binds only the endpoint namespace, not the host or household interface.

IPv6 is disabled only in these temporary benchmark namespaces. There are no
router advertisements, DHCP, DNS changes or Freebox-identity impersonation.
The new pilot's own uplink IPv4/MAC is announced in two unicast ARP replies to
the selected client only. This refreshes stale neighbor state when successive
pilots reuse an address with different ephemeral MACs; it does not announce
ownership of the household gateway address.

`tools/windows_gateway_benchmark.py` uses optional Paramiko and explicit pinned
client/VM host keys. Like earlier Windows acceptance, the password comes only
from `FAILSAFE_SSH_PASSWORD`. Use `--help` for the remaining explicit arguments.
It creates a fresh private Windows baseline and proves its actual local SYSTEM
rollback before applying anything. `ApplyBenchmark` journals a single
`198.18.71.2/32` ActiveStore route before creating it. It refuses an existing
route in the benchmark address space or using the household default as the
pilot gateway. Windows default routes, address, IPv6, DNS and NRPT stay intact.

Two downloads and two uploads of 128 MiB each use the existing Windows curl,
with one-second gaps: 512 MiB of **local** payload in total. A temporary upload
file lives inside the protected run directory and is removed after restoration.
No benchmark packages, drivers, VPNs or Windows listener services are installed.
This briefly exercises the selected Ethernet/VM path; it is not a promise of
zero shared-hardware contention.

Each curl command has bounded connect/transfer timeouts. The gateway's control
loop is limited to 120 seconds, its endpoint to 140 seconds, and the remote
launcher to 150 seconds plus a kill grace. Normal errors/SIGTERM execute
namespace cleanup. The Windows SYSTEM deadline/startup guard independently
removes its owned route if control is lost. This is not proof of arbitrary
SIGKILL recovery for namespace processes or a production topology rollback.

Final acceptance checks all eight Windows baseline groups, removes its rollback
task, verifies the host's original IPv4/IPv6 routes/rules/firewall/forwarding,
and requires forwarding-byte counters in both directions plus four counted
NAT first packets. Reports are new files in an ACL-checked private directory,
not public repository artifacts. The read-only rollout preflight now also
rejects leftover `f4g-bench-*` namespaces.

## Observed results and limits

The first complete live run measured:

| Direction | Sample 1 | Sample 2 |
| --- | --- | --- |
| Download | 932.98 Mbps | 946.21 Mbps |
| Upload | 685.97 Mbps | 684.72 Mbps |

The client reports a 1 GbE link. All four 134,217,728-byte transfers completed;
the two forwarding rules counted more than 272 MB each and the NAT rule counted
four new flows. The namespace had no Internet default, and Windows and VM host
network state were restored. These are TCP payload rates for this exact path,
not a full Ultra fibre benchmark or an independent measurement of NAT overhead.

A second complete run measured 903.82/928.81 Mbps download and 700.03/689.09 Mbps
upload. It also validated counters, the selected client's updated neighbor
identity, and both restoration checks. The benchmark is not a reason to move
normal Ultra fibre traffic through this VM.

The repeat observed a different cached uplink identity before startup and the
expected new pilot identity afterward, validating the targeted ARP refresh.
A separate SIGTERM test interrupted a ready benchmark: its namespaces were
removed and all original host route/rule/firewall/forwarding snapshots matched.
Missing/zero traffic evidence and leftover benchmark namespaces are rejected
by the respective acceptance/preflight checks.

An initial setup-order error was corrected before any client benchmark route
was installed; its Windows baseline matched afterward. A subsequent zero-flow
timeout also restored both baselines. Explicit single-client uplink identity
announcement was then added, and the complete run succeeded. Private failed-run
records are retained rather than reported as passing measurements.

This does not qualify 2.5/8/10 Gbps forwarding, IPv6/NAT66 performance, jumbo
frames, PMTUD, simultaneous household loads, long-duration stability, WAN/LTE
speed or gateway/host/storage failure bypass. HTTP is deliberately local and
unencrypted, so TLS CPU cost is not included. The endpoint and forwarding run
on the same VM and therefore share CPU; do not extrapolate these results into
a line-rate guarantee or a clean isolated kernel-forwarding benchmark.

## Topology consequence

The current APs and unmanaged switch remain unchanged. No managed-switch VLAN
isolation has been assumed. A physical controlled-gateway LAN remains a design
candidate, not an approved deployment: it must cover both the PoE-switch uplink
and devices now wired directly to the Freebox. Available multi-interface gateway
hardware, primary-path performance expectations, native IPv6 routing/delegation,
management access and independent rollback must be settled before any rewiring.
No purchase is authorized. The owner has since preferred using only the existing
Freebox/VM and cellular router for control, with no extra always-on gateway.
Physical gateway migration is not the active rollout plan; see the
[existing-device direction](EXISTING-DEVICE-DESIGN.md) and
[rollout gates](ROLLOUT-PLAN.md).
