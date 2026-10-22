# Production-path qualification and rollout status

The installed Ethernet service is armed with `ipv6_policy=best_effort` and
currently reports fibre up, LTE healthy, and takeover inactive. Normal fibre
traffic still uses the Freebox directly; the VM and 100 Mbps LTE port are not
inserted into that path. No household DHCP, IPv6 advertisement, AP or switch
configuration changed during rollout. Private reports and client identifiers
are not published with the source.

## Best-effort IPv4 policy

Default `ipv6_policy=require_disabled` preserves the original safety interlock.
Candidate source additionally supports `ipv6_policy=best_effort`, requiring
`accept_ipv6_limitations=true`. This is a separate acknowledgement, not a claim
that LAN IPv6 is disabled. Keep `lan_ipv6_disabled=false` on a live IPv6 LAN.
The shipped default remains `enabled=false`; the installed household config is
explicitly enabled after the owner's maintenance-window approval.

Best-effort takeover changes only IPv4 routing and redirects IPv4 DNS addressed
to the primary gateway. It does not take over the Freebox IPv6 router or IPv6
DNS identity. Applications using unreachable IPv6 or an IPv6-only resolver can
stall; IPv6-only services cannot be supplied by this IPv4-only backup. Startup,
status and doctor output expose these limitations. The owner accepts practical
fallback rather than perfect continuity, but deployment still needs approval.

Selected Android application tests passed real LTE use and native IPv6 recovery
without reconnecting Wi-Fi. AP-scoped steering used in those tests is not the
production ARP takeover mechanism. Windows transport compatibility is mixed;
neither success proves every household device will work. Public-address changes
also break existing sessions regardless of IP-family fallback.

A wired Windows retest with the deployment SIM completed takeover and recovery:
curl used cellular IPv4 during silent IPv6 loss, while the older .NET WebRequest
and HttpClient engines missed both 10- and 20-second deadlines. Those engines
also missed 10-second deadlines in the immediate-reject stage. All three engines
worked again after native fibre restoration. The client's eight restoration
checks and the VM host-network comparison passed. This is completed testing
with compatibility failures, not universal application acceptance.

The actual production daemon then passed a bounded wired-client ARP canary on
the selected Windows PC. A synthetic primary-WAN-down signal left the physical
fibre link untouched; only that client's IPv4 `/32` was redirected. The PC's
observed public IPv4 changed to Bouygues LTE within 15 seconds, remained stable
for a 30-second repeat, and returned to its original fibre address and Freebox
gateway MAC after a synthetic primary-up signal. The exact Windows network
baseline matched afterward, and the VM's host routes, policy rules, nftables
tables and pilot namespace state were clean. A separate timer test killed the
canary worker with SIGKILL while that PC was using LTE; a transient systemd
timer launched a recovery worker, returned the PC to its original fibre egress,
and left the VM networking clean. The Windows SYSTEM restoration checks also
matched. This is process-failure recovery while the VM remains alive, not
independent recovery from VM/Freebox/USB-host loss or a whole-house rollback.
One earlier try exposed an overly short
recovery observer relative to its four-check debounce; the threshold and
observer were aligned before the passing repeat. This validates the selected
IPv4 ARP/NAT path and recovery on one wired PC, not an actual fibre outage,
household-scale rollout, general IPv6 fallback, performance, or every client.
The private live report is kept outside the repository.

During the approved maintenance window, a second test exercised the controller's
global LAN mode rather than a client `/32`. With fibre physically connected, a
synthetic WAN-down signal caused the VM to announce the Freebox IPv4 gateway
address on behalf of the LTE path. The wired Windows client observed the VM's
MAC for the Freebox gateway, resolved DNS through that address, and reached
HTTPS through cellular IPv4 on two checks. The canary's synthetic WAN-up
transition automatically returned gateway ownership; the same client observed
the Freebox MAC and original fibre egress. A separately
armed 180-second VM rollback timer was also exercised by invoking its recovery
helper (`tools/household_lan_canary_rollback.py`) before expiry; the production
service returned to armed standby with healthy LTE and no restart. This verifies
global ARP takeover/recovery on the physical LAN from one wired client, not
individual Wi-Fi/AP client behavior, an actual ISP outage, or IPv6 failover.
Normal connectivity was confirmed after the test; AP, Freebox and DHCP/RA
configuration remained untouched.

## Disconnected production-daemon laboratory

Run as root on Linux with the project's dependencies, `ip`, and `nft`:

```sh
sudo timeout --signal=TERM --kill-after=20 300 python3 tools/production_path_lab.py --source ./freebox_ethernet.py
```

Four isolated namespaces contain a virtual client, switch, gateway and upstream.
There is no physical uplink or household ARP announcement. The actual candidate
daemon runs its decision loop, backup health, packet sniffer, ARP announcements,
policy routing, NAT and cleanup. Only the Freebox API and upstream endpoints are
fixtures. TCP/plain HTTP on port 443 is not TLS or real Internet validation.

Eight checks passed in preparation: native baseline; ARP takeover with SNAT and
UDP/TCP DNS redirection; short recovery suppression; unknown-API grace/release;
both-path failure and stable release; normal failback/SIGTERM cleanup; daemon
restart and SIGKILL journal recovery; namespace/host-network restoration.
Timers are accelerated and do not measure household detection latency.
Runtime files now use private directories under RAM-backed `/run`, matching the
production daemon rather than adding rapid status writes to the USB root disk.
The namespace pilot uses the same runtime placement, and confirms host cleanup
inside its finalizer even if a test fails. One wired attempt timed out waiting
for a namespace IPv6 RA transition before the completed retest; the precise
cause was not established, and moving runtime files is not proof of that cause.
The latest serial run of all eight checks passed; a concurrent earlier rerun
timed out during initial readiness. That timeout is retained as a failed run,
not evidence of a successful stress/restart test or a proven storage diagnosis.

SIGKILL recovery explicitly invokes a fresh process to consume the journal. It
is not proof of independent host-failure bypass, a real VM reboot, or systemd
recovery on the deployed machine. A physical selected-client ARP takeover and
the final approved outage remain separate acceptance gates.

## Bounded standby LTE load

`tools/lte_load_acceptance.py` uses pinned SSH to the cellular router, checks
its exclusively cellular default route, and downloads a fixed 1 or 10 MiB OVH
test file over certificate-verified HTTPS. It consumes the stream without
storing its body. A detached 45-second process-group guard bounds the transfer;
concurrent and subsequent DNS UDP/TCP and HTTPS checks are recorded in a new
private report. Configuration and firewall must match baseline afterward.
No client is steered to LTE by this tool.

A 10 MiB transfer passed with every concurrent/subsequent health check healthy.
An earlier Cloudflare download endpoint returned HTTP 403 with zero bytes;
that attempt did not provide load qualification. The successful test is a
small congestion check, not sustained saturation, throughput, MTU/PMTUD or
long-duration reliability qualification. It does not establish the cause of
the earlier unlabelled controller error during a phone speed test.

The installed monitor-only service also survived a controlled lifecycle check:
a clean systemd restart preserved the host network, then a forced SIGKILL of
the monitor process produced one systemd restart, a running service, and a
passing read-only preflight. Takeover remained disabled throughout. This
qualifies the Linux service manager's process-restart path only; it does not
simulate a VM/Freebox/USB-host failure while actively forwarding LTE traffic.
The updated candidate preflight also rejects leftover production-canary run
directories or transient timer units, in addition to stale lab namespaces.

## Remaining boundaries

- Selected Android, TV, and Windows tests are not a guarantee for every
  household application or device. Windows .NET transports have known timeout
  cases when IPv6 is silently unavailable.
- The household rollback helper disables takeover, restarts the controller,
  and verifies the Freebox default route, policy rules, route table and nftables
  state. It passed from armed standby. It cannot run if the Freebox VM or its
  host/storage fails; recovery then depends on the Freebox or VM returning.
- No physical fibre interruption was performed. The global ARP takeover ran
  with fibre connected and used a synthetic primary-down signal; only one wired
  client was directly observed, so wireless/AP and other client behavior remain
  unqualified. A real ISP outage remains untested.
