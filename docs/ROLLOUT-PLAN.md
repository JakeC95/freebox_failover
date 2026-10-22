# Household rollout: safety checks and operation

Preparation alone never authorizes activation. The owner approved this
maintenance window; the installed service is now armed with the acknowledged
best-effort IPv6 policy. The preflight below is only for a disabled service and
continues to report `rollout_authorized: false` by design. Never infer approval
from a passing pilot or preflight. Do not change Freebox DHCP, DNS, prefix
delegation, advertisements or wiring as part of IPv4 failover.

The owner has subsequently accepted a best-effort IPv4 backup policy rather than
complete IPv6 continuity. Candidate source offers an explicitly acknowledged
policy, enabled in the installed service only after approval. The
[production qualification notes](PRODUCTION-QUALIFICATION.md) supersede older
requirements for universal application fallback, without removing representative
client tests, truthful IPv6 limitations, or maintenance-window approval.

## Read-only preflight

On the existing Linux gateway:

```sh
sudo python3 /opt/freebox-failover/tools/rollout_preflight.py
```

This checks disabled takeover, the unbypassed IPv6 interlock, a fresh monitor-only
heartbeat, primary API state, configured service watchdog/restart policy,
512 MiB disk and 128 MiB available-memory headroom, no leftover pilot namespaces,
a clean checkout, no leftover production-canary runtime/timer state, and an
existing completed source/config installer backup.
Resource thresholds are preparation headroom, **not** a throughput guarantee.
Backup presence is not proof that a production network rollback works.

Optional `--output` saves a new mode-0600 JSON file in an existing root-owned,
private directory; an existing report is never overwritten. Reports contain
check verdicts, revision and resource totals, not tokens or household inventory.
Inspection failure exits nonzero. Successful inspection still reports
`production_ready: false` and `rollout_authorized: false`; six independent
deployment gates remain explicit. It makes no network changes or API writes.

Live preparation checks pass on the current VM. A running pilot correctly makes
the clean-namespace check fail. Private report creation, refusal to overwrite an
existing report, and refusal to write in a mode-0755 parent were also exercised.
These results must be refreshed against the exact deployment revision.

## Architecture gate: not settled by the pilot

The current production daemon implements IPv4 ARP takeover only. The pilot's
family-aware IPv6 policy does not magically extend that production mechanism.
An independent router cannot withdraw the Freebox's IPv6 router identity merely
by withdrawing its own advertisement. Test-only high-priority unicast RAs are
not the final household solution.

One previously evaluated candidate was a separately controlled routed client segment
with one gateway/RA/DNS policy, native IPv6 while fibre is healthy, and fast
IPv4 fallback when the available cellular upstream is IPv4-only. It requires an
actual segment/wiring plan, an agreed prefix/delegation or translation policy,
and a way to place the required wired and wireless clients behind that gateway.
Do not assume the Freebox's built-in Wi-Fi, switch or prefix configuration can
provide that arrangement without verifying them. No purchase is authorized.

The owner prefers decision-making on the existing Freebox/VM and cellular router,
with no additional always-on gateway and no dependency on the Windows test PC.
That is now the preparation direction, not a request to buy another router.
Keep normal fibre traffic directly routed by the Freebox. The
[existing-device architecture constraints](EXISTING-DEVICE-DESIGN.md) describe
what is proven and what remains unresolved, especially IPv6 control.

The household has now confirmed external OpenWrt APs, not Freebox Wi-Fi, and an
unmanaged PoE switch. A [read-only AP audit](ACCESS-POINTS.md) confirms working
bridged radios/roaming with unchanged configuration and private backups. Keep
those APs untouched; do not assume switch VLAN isolation or move only Wi-Fi
clients while forgetting devices connected directly to the Freebox.

The selected 1 GbE client's local VM forwarding path has been measured, and the
normal fibre path still bypasses the VM. Establish what clients do if the VM,
its USB storage or its host fails during active LTE forwarding. A gateway that
fails over the ISP but turns a VM outage into a household outage is not yet a
failsafe design. Keep the 100 Mbps LTE router out of the normal fibre data path.
Do not promise Ultra line-rate forwarding or automatic VM-failure bypass.
If topology requires equipment or a material performance/security tradeoff,
present that decision to the owner before implementing it.

## Acceptance matrix and existing evidence

| Condition | Evidence/status | Deployment requirement |
| --- | --- | --- |
| Fibre IPv4/IPv6 and DNS | Namespace and selected Windows client pass | Repeat with final gateway and intended clients |
| Sustained primary failure, healthy LTE | Automatic namespace and Windows traffic pass | Repeat with deployment SIM and approved real upstream cut |
| Short failures/recovery flapping | Automatic namespace passes | Preserve debounce and minimum dwell in final controller |
| LTE down / both paths down | Namespace selection/hold checks pass | Confirm final DNS failure behaviour and no route oscillation |
| IPv6-only primary failure | Independent pinned IPv6 probe and bounded namespace scenario | Require working fibre IPv4 to stay on fibre; withdraw only controlled IPv6 default |
| IPv6 recovery | Three healthy pinned IPv6 samples restore pilot default | Recovery probe must work while client IPv6 default is withdrawn |
| Windows SLAAC/RDNSS/router expiry | Selected-client unicast wire capture and SYSTEM rollback pass | Repeat on final segment; not proof of household RA coexistence |
| Other client families/applications | Android and TV deployment-SIM rehearsals pass; selected Windows curl works but older .NET transports miss deadlines | Accept known app limitations; remaining clients/calls/VPN/local discovery remain unqualified |
| Unusable IPv6 with working cellular IPv4 | Android applications pass; [Windows application comparison](APPLICATION-FALLBACK.md) finds .NET deadline failures despite curl fallback | Explicitly acknowledged best-effort policy; never promise universal fallback |
| VM/host/USB failure, reboot | Monitor-only service restarts after SIGKILL; active-failover host loss untested | Define recovery/downtime expectations and exercise or explicitly accept host-loss behavior |
| Throughput, MTU/PMTUD and long-running stability | [Selected-client local IPv4 NAT benchmark](GATEWAY-BENCHMARK.md) passes on a 1 GbE client; a bounded LTE load check passes; other limits unqualified | Confirm this scope is adequate; normal multi-gig fibre bypasses the VM, LTE is the constrained path |
| Production rollback | Windows SYSTEM guard and VM timer recovery after selected-worker SIGKILL pass for one PC | Rehearse rollback for the full household topology; neither guard survives VM/Freebox/USB-host loss |

IPv6 health currently verifies TLS to two addresses of one provider and does not
claim multi-provider outage diagnosis or independent DNS-over-IPv6 validation.
Three failed samples suppress only the pilot IPv6 Internet default; three good
samples restore it. Local prefix/DNS remain available. IPv4 path selection has
its separate health/hysteresis. All fault rules and pinned route tables live in
the pilot namespace, not the host or household gateway.

## Rollback helper

The root-only `tools/household_rollback.py` disables takeover, restarts the
service, and refuses success unless monitor-only mode, the Freebox default
route, and absence of failover policy routes and firewall state are verified.
It passed a live rollback rehearsal from armed standby. To arm a five-minute
automatic rollback before a future config change:

```sh
sudo systemd-run --unit=failsafe4g-rollout-guard.timer --on-active=5m \
  /usr/bin/python3 /opt/freebox-failover/tools/household_rollback.py
```

Keep the timer until the service and representative clients pass the window's
checks; stop it only after confirming the service is armed and healthy.

## Final-window procedure

1. Present the exact topology/config diff, tested release revision, expected
   disruptions, rollback trigger/deadline and any required physical actions.
   Ask the owner to choose a window and explicitly approve activation.
2. Save private configuration/state baselines and verified release backups for
   every changed device. Ensure local console or physical recovery is available.
3. Arm the independently exercised rollback deadline before the first change;
   confirm management remains reachable without relying on the new data path.
4. Activate one canary first. Check native fibre IPv4/IPv6, DNS and local access,
   then perform the approved fibre fault and verify cellular egress/application
   fallback, restoration, hysteresis and rollback while recording live logs.
5. Expand in agreed batches only if the canary passes. Never cut the fibre or
   change all household DHCP/RA settings as an exploratory test.
6. Verify representative clients after restoration. Disarm rollback only after
   required checks pass and the owner accepts the result. Retain private logs
   and the exact revision/configuration for recovery.

Expect established Internet sessions to break when the public address changes;
failover does not migrate TCP/VPN/call state between unrelated upstreams. An
IPv4-only SIM cannot provide arbitrary IPv6-only Internet connectivity. Neither
limitation should be hidden by a successful HTTP fallback test.
