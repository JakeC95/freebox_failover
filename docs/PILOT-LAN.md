# Separate Internet-connected pilot LAN

## Scope

`tools/dual_stack_pilot.py` creates a temporary gateway and one Linux test client
in separate network namespaces on the existing Debian VM. It does not move any
household client, change the PC connection, alter Freebox settings, or enable the
production failover daemon. It is a bounded experiment, not a persistent service.

The gateway uses an IPVLAN L2 uplink sharing the VM NIC's Ethernet identity,
with its own checked IPv4 address and independently generated IPv6 identity.
The client connects only to a private veth LAN. Router advertisements are sent
only on that veth; the worker checks its link type before sending. The upstream
interface receives the Freebox's real advertisements; it never sends RAs there.
Neither host forwarding nor host firewall/routing policy needs modification.

The pilot gateway provides:

- A stable private IPv4 gateway/DNS address and ULA IPv6 gateway/DNS address.
- A non-caching UDP/TCP DNS proxy on both families, restricted to the pilot LAN.
- IPv4 masquerading through either upstream gateway.
- Temporary IPv6 ULA-to-public masquerading on fibre only.
- Controlled default-router advertisement/withdrawal, keeping local IPv6 and
  the local DNS endpoint reachable on the IPv4-only cellular path.
- Stateful forwarding with unsolicited upstream forwarding denied. Forwarded
  access to private IPv4 ranges, IPv6 ULA/link-local and observed household
  uplink IPv6 prefixes is rejected; upstream DNS queries originate at the gateway.

This deliberately uses NAT66 to avoid allocating or changing any Freebox prefix
delegation during the pilot. It is **not** a decision to adopt NAT66 for the
household. A final native routed-prefix design needs a separate delegation,
firewall and throughput review. Normal fibre traffic never traverses the MR6400.

## Running

Dependencies are Python 3, Scapy, iproute2, nftables, curl with a trusted CA store,
ping and Linux network namespace privileges. No extra daemon/package was needed
on the existing VM.

First inspect the upstream DHCP pool, reservations, address inventory and existing
host addresses. Choose an unused private uplink address **outside the DHCP pool**,
on the same subnet as the primary and backup gateways. ARP conflict detection is
an additional guard, not proof that a sleeping device has no static assignment.
The tool refuses an address already on the host or equal to a gateway and sends
three ARP probes before assigning it. Do not copy an arbitrary example address.

```sh
sudo timeout --signal=TERM --kill-after=20 240 python3 tools/dual_stack_pilot.py \
  --run --interface enp0s5 --uplink-address CHECKED_UNUSED_ADDRESS/PREFIX \
  --primary 192.168.1.254 --backup 192.168.1.253
```

By default the controller runs explicit primary, backup and primary phases,
then removes the pilot. The optional automatic scenario below instead makes
decisions from real path-pinned health probes. Its lock prevents overlapping
pilot runs. SIGTERM/SIGHUP use normal
cleanup; SIGKILL or power loss cannot run Python cleanup. Inspect `ip netns list`
and pilot worker processes after any abnormal termination before another run.
Do not delete unrelated namespaces. The namespace-specific resolver file is
removed on normal cleanup, and host routes (excluding expiring RA timers), IPv4
rules, nftables and forwarding settings are compared with the starting snapshot.

## Live results and limitations

The real VM pilot passes:

1. Attempted client access to household management is rejected, with the matching
   firewall reject counter incrementing.
2. Resolved-hostname, certificate-verified HTTPS through fibre over IPv4 and IPv6.
3. Validated DNS responses over both UDP/TCP and IPv4/IPv6 DNS transport in every
   phase, using the same client-side DNS endpoint throughout.
4. Verified HTTPS through a different cellular IPv4 public egress after switching
   only the pilot gateway's default route and DNS upstream.
5. Withdrawal of the client's IPv6 default, failed off-link IPv6 HTTPS, successful
   local IPv6 ping and working unforced-family HTTPS on the cellular path.
6. Restoration of the original fibre IPv4/IPv6 egress and DNS behaviour.
7. Complete removal of the pilot with the host network state matching baseline.

A separate SIGTERM interruption test also passes: pilot workers/namespaces and
the per-namespace resolver are removed. The final complete pre-publication run
includes the household-access rejection rule and both-family UDP/TCP DNS checks.

The first two DHCP-based uplink attempts timed out without obtaining a lease and
cleaned up. The working pilot instead uses a pre-checked out-of-pool address and
IPVLAN. No DHCP configuration, existing lease or household prefix was changed.

The namespace client uses an explicit resolver configuration. Actual client OS
RDNSS ingestion, Windows/Android/Apple behaviour, existing connection migration,
MTU edge cases and gigabit forwarding capacity are not established by these
checks. The default scenario uses explicit phase switching. The optional automatic
scenario detects namespace-injected faults, not a physical fibre outage.
The production daemon remains
monitor-only, with its IPv6 safety interlock intact. No test-client LAN is left
running after successful completion.

Kernel references: [IPVLAN](https://docs.kernel.org/networking/ipvlan.html),
[IPv6 forwarding and accept_ra](https://docs.kernel.org/networking/ip-sysctl.html).

## Automatic outage-detection scenario

Add `--automatic` to the same command, allowing a 360-second outer timeout:

```sh
sudo timeout --signal=TERM --kill-after=20 360 python3 tools/dual_stack_pilot.py \
  --run --automatic --interface enp0s5 \
  --uplink-address CHECKED_UNUSED_ADDRESS/PREFIX \
  --primary 192.168.1.254 --backup 192.168.1.253
```

Each observation checks the two upstreams independently. Socket marks `0x71`
and `0x72` select namespace-only tables/rules `7171` and `7172`, pinned respectively
to the Freebox and LTE gateway. A failed primary cannot silently probe through
the selected backup default route. Each path must return a valid DNS A answer
through its own gateway and a certificate-verified HTTPS 200 response. HTTPS
tries `1.1.1.1` and then `1.0.0.1` with verified `one.one.one.one` TLS identity.
These are [Cloudflare addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/),
not independent providers; production endpoint diversity remains future work.
This does not replace the roaming carrier's DNS proxy with public UDP DNS.

The decision policy requires:

- Three consecutive failed primary observations before takeover.
- Two consecutive healthy backup observations before selecting cellular.
- Three consecutive healthy primary observations before restoring fibre.
- At least ten seconds between transitions; short recovery bursts reset on
  another failure. Unknown observations prevent a transition.
- No oscillation onto a known-failed alternative when both paths fail.

Failure injection changes only the gateway namespace: counted reject rules
block marked probes for the affected path, an unreachable main default simulates
selected-path IPv4 loss, and a primary fault rejects forwarded Internet IPv6.
The controller is not given fabricated healthy/unhealthy values. It must observe
actual socket/DNS/TLS failures, verify the other path and then change its route,
DNS upstream and private-LAN IPv6 advertisement. Household fibre remains up.

The complete live scenario passed in 94.1 seconds, including warm-up and injected
faults. It verifies transient-failure suppression, refusal to select broken
cellular, automatic takeover once cellular recovers, real cellular HTTPS/DNS,
both-path failure without oscillation, suppressed flapping recovery, and automatic
restoration of fibre IPv4/IPv6. Exactly two transitions occurred. Total scenario
duration is not a promised outage-detection or switchover latency.

Deterministic policy checks cover thresholds, dwell, unknown observations and
recovery; 50,000 seeded randomized observations produced 269 transitions, all
meeting the policy's guards. SIGTERM during an injected primary outage also
removes the pilot fault rules, workers and namespaces, with the host's IPv4/IPv6
routes, rules, firewall and forwarding matching the original snapshot. Route
changes are applied before publishing the new DNS/RA phase, and an exited pilot
worker aborts automatic monitoring rather than continuing with missing services.
This is still an opt-in pilot, not an installed
automatic household gateway. IPv6-only upstream failure detection, actual client
OS behaviour, physical-link outages and real-device acceptance tests remain open.
