# Windows application fallback under unavailable IPv6

This is a selected-client compatibility experiment, not household activation or
a solution to the Freebox IPv6 router-control gate. The APs, PoE switch, Freebox
DHCP/RA/delegations and production takeover setting remain unchanged.

## Test construction

`tools/windows_application_fallback.py` creates a fresh protected Windows
baseline, proves the actual local SYSTEM canary rollback, and starts the bounded
physical-client namespace pilot. It uses optional Paramiko, pinned host keys,
an environment-only `FAILSAFE_SSH_PASSWORD`, and a new ACL-checked private report.
See `--help` for explicit host/VM, key, uplink and report arguments.

Only the selected Windows client receives the existing journaled temporary
IPv4 split routes, public-IPv6 route and two exact test-domain NRPT rules. Its
original IPv6 default router is not removed, but the more-specific temporary
test route directs Internet IPv6 through the pilot. No physical-LAN RAs are
sent. The pilot refreshes its own temporary uplink identity with two ARP replies
addressed only to the selected client, never claiming the Freebox's identity.

The new `client_ipv6_blackhole` fault is accepted only with an explicit physical
client. A counted namespace prerouting rule matches that client's Ethernet
source, global IPv6 source/destination and pilot uplink before silently dropping
the packet. Prerouting is intentional: a later unreachable route/forward reject
must not turn the silent-loss scenario into an immediate ICMP error. It does
not alter independently marked primary/cellular health probes or other clients.

The sequence is:

1. Verify dual-stack DNS and successful forced IPv4/IPv6 HTTPS through fibre,
   including translated IPv6 evidence rather than bypassing the pilot.
2. Observe ordinary curl, PowerShell `Invoke-WebRequest` and .NET Framework
   `HttpClient` requests to the same certificate-verified HTTPS trace endpoint.
3. Enable selected-client IPv6 silent loss, then inject primary-path failure.
   The automatic controller must independently verify/select actual cellular.
4. Require successful forced IPv4 with a different egress from fibre and failed
   forced IPv6 with counted drops. Observe all three unforced application paths,
   repeat curl, then use extended 20-second deadlines for the .NET engines.
5. Remove silent loss while keeping cellular selected; compare ordinary requests
   against the pilot's existing immediate rejection/unavailable-route behaviour.
6. Recover fibre automatically, repeat forced-family and ordinary application
   controls, restore all eight original Windows baseline groups, disarm its
   local task, and verify complete VM host network cleanup.

The Windows probe uses existing curl and built-in .NET/PowerShell; it installs
no browser, VPN, driver or persistent agent. Proxies are disabled only within
each probe process, with normal certificate checking retained. .NET probes use
TLS 1.2. Reported times include process-local initialization/error handling and
are not pure network RTT or promised failover latencies.

For the observed repeat, the orchestrator samples TCP connections owned only by
the probe PowerShell process while .NET calls run. The protected metadata file
identifies that PID; private reports retain remote endpoints and states for
diagnosis. This is not a capture of household browsing or unrelated processes.
The curl subprocess is separate and is not attributed to its parent PID.

## How to interpret observations

Successful curl fallback is not proof that every application falls back. A
deadline failure is not proof that the application never retries later. A
failure observed with IPv6 unavailable is not, by itself, proof that IPv6 was
the sole cause; inspect the process-specific TCP observations and matched
baseline/recovery controls before attributing it.

The rule drops all selected-client public IPv6 during that test interval,
including background applications on that client. Its per-interval drop counts
are not per-process attribution and must not be presented as such. No other
household client's configuration or traffic is selected by the fault rule.

Test DNS is explicitly reachable through the pilot's restricted NRPT mapping.
This does not qualify original household IPv6 DNS servers, cached AAAA answers,
DoH/DoT, IPv6 literals, long-lived sessions, other client OSes, browser engines,
VPNs or TV/IoT applications. It does not establish a production way to suppress
the Freebox's existing IPv6 route. Household takeover stays disabled regardless
of whether the test completed cleanly.

Application failures are recorded as findings, not hidden as harness success.
`testing_completed` means the scenario and restoration completed; inspect
`limitations` and individual observations. A fresh report is never overwritten,
and detailed reports remain private rather than entering Git.

## Live findings

Two complete runs reproduced the difference. In the observed repeat:

| Request path | Fibre baseline | Cellular + silent IPv6 loss | Cellular + reject policy | Fibre restored |
| --- | --- | --- | --- | --- |
| curl, unforced family | Succeeded over IPv6 | Succeeded over IPv4, 1.44 s; repeat 2.46 s | Succeeded, 1.45 s | Succeeded |
| PowerShell web request | Succeeded, 0.132 s | Timed out at 10 s and again at 20 s | Timed out at 10 s | Succeeded, 0.139 s |
| .NET Framework HttpClient | Succeeded, 0.180 s | Timed out at 10 s and again at 20 s | Timed out at 10 s | Succeeded, 0.180 s |

Forced IPv4 over cellular succeeded with TLS 1.2, the same TLS version used by
the successful baseline .NET requests. Forced IPv6 failed under the silent-drop
control. During the stalled .NET calls, process-owned TCP samples showed IPv6
port-443 connections in `SynSent` (runtime enum value 3), not an established TLS
session. No IPv4 connection was seen in those samples. Sampling does not prove
that no short-lived attempt occurred between samples, nor establish the exact
runtime retry algorithm. It does provide more specific evidence than a generic
HTTP timeout or a claim that cellular was entirely unavailable.

The `immediate_reject` stage name describes the configured reject/unreachable
policy, not a wire-level assertion that each socket received an immediate ICMP
error. Error delivery/rate limiting and application handling were not separately
qualified. The observed result is that this policy did not prevent the stalls.

Both runs recovered fibre IPv4/IPv6 and all three application controls. All
eight Windows baseline groups matched after restoration, the local rollback
tasks were removed, and VM host network cleanup was confirmed. Private reports
retain the failed observations; these are compatibility failures, not permission
to relax the IPv6 production interlock.

**Conclusion:** redirecting IPv4 and hoping applications handle unusable IPv6 is
not a sufficiently reliable household-wide design on this evidence. Immediate
rejection alone also did not rescue the two tested .NET request paths within
the deadlines. Before rollout, establish a real IPv6 availability/control policy
or explicitly agree a different limitation with the owner. Do not generalize
these .NET Framework results to every browser, operating system or .NET release.

Afterward the original twelve-group automatic namespace regression passed in
154.4 seconds with exactly two IPv4 path transitions and complete host cleanup.
Five unsafe physical-client MACs were also rejected before any network command.
A final client inspection found no remaining test public-IPv6 route override,
tagged NRPT rules or local rollback tasks.
