# Single-client Windows router-discovery acceptance

The Windows client now passes actual SLAAC, RDNSS ingestion, default-router
installation/withdrawal, and independent router/DNS lifetime expiry. Testing is
opt-in and confined to one explicitly selected client's Ethernet and link-local
IPv6 destination. No multicast RAs, Freebox changes, adapter resets, VPN driver
installation or physical bridging are used.

This is targeted unicast testing over the existing LAN, **not** a physically
separate LAN. Ordinary switches/NICs deliver the frames only to their addressed
recipient. A separate source-filtered wire capture validates the actual probe
frames, rather than relying solely on their construction in software.

## Safety boundaries

`dual_stack_pilot.py` accepts `--unicast-ra-peer` only with external control and
an explicit physical client IPv4/MAC pair. It requires a link-local peer and a
dedicated `fd00::/8` /64 absent from that client's initial configuration.
`windows_ra_acceptance.py` obtains the MAC/link-local address from the selected
client interface over administrator SSH, not by guessing from its IPv4 address.

The packet builder rejects multicast/zero/malformed Ethernet addresses, duplicate
source/destination identities, non-link-local IPv6 peers, non-ULA prefixes,
reserved preferences, unbounded lifetimes and non-boolean retirement flags.
Frames have hop limit 255, explicit unicast destinations and their own router
identity; they do not impersonate the Freebox.

The bounded probe permits router lifetimes of 0, 15 or 30 seconds, DNS lifetimes
of 0 or 15 seconds, and explicit low/high router preference. Prefix lifetimes
are 120 seconds valid and 60 seconds preferred. Retirement advertises zero
lifetimes. A zero router lifetime does not itself remove the independently timed
prefix or DNS information.

The default preference is low. In the first run Windows learned SLAAC and DNS
but did not expose the low-priority router as an installed default; cleanup
matched the baseline. The selected-client test then used short-lived high
preference to observe default installation and withdrawal. This can temporarily
route **that client's** IPv6 traffic through the tested gateway; it is not an
approved overlapping-router production design or authorization to multicast
high-priority RAs around the household.

## Local rollback and observation

The existing private baseline/SYSTEM rollback guard is extended with:

- `PrepareRA`: verify the baseline, reject an already-used prefix/router,
  verify the armed timer and journal ownership **before** sending any RA.
- `ReadRA`: report learned addresses with `PrefixOrigin`, matching default
  routes, all interface defaults, DNS servers and observation time.
- `Restore`: remove only the recorded probe router/prefix/addresses and tagged
  test state, allow short-lived learned DNS to expire, and verify the original
  configuration before clearing the journal or disarming the task.

Windows may retain SLAAC addresses after a zero-valid-lifetime advertisement due
to the unauthenticated-lifetime protection in RFC 4862. The local SYSTEM guard
therefore removes the dedicated owned prefix/address state explicitly; retirement
packets alone are not treated as proof of rollback.

`capture_probe_ra.py` captures only RAs from the private namespace router's
specific MAC on the VM uplink. It stores destination-confinement verdicts,
router lifetimes and hop limits, not browsing payloads or other devices' traffic.
The capture is bounded and its owned process is stopped after validation.

## Reproducible workflow

Use `windows_ra_acceptance.py --help` for explicit client/VM, known-hosts, key,
checked unused uplink address and private report-path arguments. Like the earlier
Windows acceptance helper, it uses the optional isolated Paramiko tooling and
`FAILSAFE_SSH_PASSWORD` environment variable. Host keys must already be verified;
credentials, inventories and private reports must never be committed.

The orchestrator creates a fresh protected Windows baseline, proves the local
SYSTEM canary rollback, starts a bounded namespace gateway and source-filtered
capture, arms the actual RA-state journal, and runs:

1. Zero-default-lifetime RA: Windows learns two SLAAC addresses and the local
   RDNSS server; UDP/TCP DNS over local IPv6 works without a new default route.
2. Short high-preference RA: Windows installs the probe default (observed metric
   16, alongside the Freebox's metric 256).
3. Zero router lifetime: the probe default disappears before natural expiry,
   while local SLAAC addresses and DNS remain usable.
4. Fifteen-second router/DNS lifetimes: both expire while the longer-lived local
   SLAAC addresses remain.
5. Retirement plus the actual SYSTEM task: learned probe state is removed and
   all eight baseline checks match; the task is then removed.
6. Gateway/capture shutdown: VM host networking matches its original snapshot,
   and Windows is rechecked after the final retirement packets.

The complete live run passes. Fourteen captured probe RAs all had the intended
single-client destination and hop limit 255; RDNSS was learned even when the
router lifetime was zero. The original static IPv4, interface settings, DNS,
active/persistent routes and NRPT configuration match after cleanup.

Before live use, serialization checks additionally verified destination and
lifetime constraints, independent prefix/DNS options, retirement and negative
safety cases without sending any packets.

## Still not established

This does not validate other operating systems, Wi-Fi RA filtering, concurrent
advertisements on every household client, production prefix delegation, VM
throughput, IPv6-only upstream failure detection or an approved final topology.
Automatic household takeover remains disabled. No persistent client RA rule or
test prefix is left behind by successful cleanup.

References: [RFC 4861 RA processing](https://www.rfc-editor.org/rfc/rfc4861.html#section-6.3.4),
[RFC 8106 DNS lifetimes](https://www.rfc-editor.org/rfc/rfc8106.html#section-5.1),
[RFC 4862 lifetime protection](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.5.3).
