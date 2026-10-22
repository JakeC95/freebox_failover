# Household rollout: preparation and approval gates

Household activation is **not authorized** by permission to prepare. Keep the
installed Ethernet service monitor-only, keep its IPv6 safety interlock intact,
and do not change Freebox DHCP, DNS, prefix delegation, advertisements or wiring
until the owner has explicitly approved a maintenance window. Never interpret
passing a pilot or the preflight below as permission to activate.

## Read-only preflight

On the existing Linux gateway:

```sh
sudo python3 /opt/freebox-failover/tools/rollout_preflight.py
```

This checks disabled takeover, the unbypassed IPv6 interlock, a fresh monitor-only
heartbeat, primary API state, configured service watchdog/restart policy,
512 MiB disk and 128 MiB available-memory headroom, no leftover pilot namespaces,
a clean checkout and an existing completed source/config installer backup.
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

The preferred design to qualify is a separately controlled routed client segment
with one gateway/RA/DNS policy, native IPv6 while fibre is healthy, and fast
IPv4 fallback when the available cellular upstream is IPv4-only. It requires an
actual segment/wiring plan, an agreed prefix/delegation or translation policy,
and a way to place the required wired and wireless clients behind that gateway.
Do not assume the Freebox's built-in Wi-Fi, switch or prefix configuration can
provide that arrangement without verifying them. No purchase is authorized.

Before selecting it, measure forwarding on the actual VM path and establish
what clients do if the VM, its USB storage or its host fails. A gateway that
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
| Other client families/applications | Not established | Representative Apple/Android/Linux/IoT as applicable; calls/VPN/TV/local discovery |
| VM/host/USB failure, reboot | Production topology not established | Independently verified recovery or explicitly accepted downtime |
| Throughput, MTU/PMTUD and long-running stability | Not established | Measure final path without silently accepting a fibre bottleneck |
| Production rollback | Only pilot rollback and installer backup proven | Rehearse selected topology with an independent deadline guard |

IPv6 health currently verifies TLS to two addresses of one provider and does not
claim multi-provider outage diagnosis or independent DNS-over-IPv6 validation.
Three failed samples suppress only the pilot IPv6 Internet default; three good
samples restore it. Local prefix/DNS remain available. IPv4 path selection has
its separate health/hysteresis. All fault rules and pinned route tables live in
the pilot namespace, not the host or household gateway.

## Final-window procedure, once all gates are satisfied

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
