# Reversible real Windows client acceptance

The real Windows 10 Pro Ethernet client passes certificate-verified fibre IPv4
and IPv6, automatically selected cellular IPv4, unforced-family HTTPS fallback,
UDP/TCP DNS, retained local IPv6 and automatic fibre IPv4/IPv6 recovery. Its
saved network configuration matches after restoration. The production daemon
remains monitor-only: this is bounded single-client acceptance, not permission
to take over the household gateway.

## What this test does differently

The Windows PC remains on its existing Ethernet LAN with its original static
address, subnet, default gateways, DNS servers, IPv6 addresses and discovery
settings. No physical rewiring or additional VPN software is needed.

Temporary ActiveStore routes `0.0.0.0/1` and `128.0.0.0/1` send IPv4 Internet
traffic to the pilot gateway. `2000::/3` sends current global-unicast IPv6 Internet
traffic to its link-local IPv6 gateway. Existing, more-specific connected LAN
routes remain preferred, so local administration remains reachable independently
of the pilot's Internet state. Two exact-name NRPT rules send only the test
domains to the pilot DNS proxy; interface DNS settings are not overwritten.

The physical gateway uses a MACVLAN namespace uplink: unlike IPVLAN L2, it can
receive forwarded packets whose IP destination is not a local namespace address.
Forwarding is authorized only for the explicit physical client's Ethernet MAC,
with an additional IPv4 source-address check. Its traffic is masqueraded through
the selected upstream, including NAT66 on fibre. Inbound DNS is limited to the
client's IPv4 source. Redirect generation is suppressed so Windows does not
learn a shortcut around the gateway. No RA is sent on the household interface.

During IPv4-only backup, the pilot returns IPv6 unreachable errors rather than
allowing IPv6 Internet traffic to escape through the still-working fibre path.
Windows must fall back to IPv4. The temporary Windows `2000::/3` route remains;
this is **not** a Windows SLAAC/RA-default-withdrawal test. The private veth client
continues to exercise actual RA withdrawal separately. An isolated physical LAN
with real client RA/RDNSS processing remains a production-design requirement.

## Local rollback must be proved first

`tools/windows_client_pilot.ps1` runs as administrator. Each run uses a new direct
child of `C:\ProgramData\failsafe4g-tests`, protected for SYSTEM and Administrators.
It records adapter identity, IP addresses, interface flags/metrics, active and
persistent routes, DNS settings and existing NRPT rules. It refuses to overwrite
a run directory or pre-existing test-prefix routes/NRPT policy.

The preparation sequence is:

1. `Snapshot`: record the client baseline with its existing IPv4 address.
2. Copy the same script into that protected run directory.
3. `Arm`: register a SYSTEM rollback task for ten minutes later and at startup.
4. `TestRollback`: add a harmless documentation-only `/32` canary route and start
   the actual rollback task. Require a receipt confirming the baseline matches.
5. The orchestrator checks this receipt, rechecks the baseline and refreshes the
   timer before applying real test routes. At least five minutes must remain.

Rollback journals intended routes before creating them, removes only the owned
route tuples and uniquely tagged NRPT rules, verifies the baseline, and clears
the journal only after success. A failed verification retains the journal for
retry/inspection. The task is removed only after restoration is verified.
Private baselines and verification receipts are retained as audit evidence.
Execution-policy bypass is process-local; system execution policy is not changed.

## Orchestration and verification

The optional tools `windows_client_remote.py` and `windows_client_acceptance.py`
require Paramiko in an isolated local tooling environment, not in the failover
daemon's dependencies. Both reject unknown SSH host keys and take the Windows
password only from `FAILSAFE_SSH_PASSWORD`, never from source or a password CLI
argument. Use independently verified known-hosts files. Do not publish private
baseline JSON, account names, MAC addresses, credentials or public egress IPs.

The acceptance tool takes explicit Windows/VM host, user/key, known-hosts,
protected run-directory, client MAC, checked unused gateway address and private
report-path arguments; see `--help`. It uploads a pilot script to the VM and runs
it with a maximum lifetime, leaving the installed production service unchanged.

`dual_stack_pilot.py --automatic --external-control` exposes a root-private
file-based control/status directory, never a public control API. It is bounded
to five minutes after readiness. Only that controller's injected faults are
commanded; automatic health observations still determine takeover/recovery.

Checks include:

- A working DNS proxy before any Windows routing change.
- Fibre IPv4/IPv6 verified HTTPS and counted physical forwarding/DNS packets.
- A fibre IPv6 source distinct from the Windows client's native addresses,
  proving that the pilot NAT path was used rather than bypassed.
- Sustained primary-path failure causing automatic selection of cellular.
- A different cellular IPv4 egress and successful unforced-family Windows HTTPS.
- Failed IPv6 Internet access but successful local link-local IPv6 ping.
- Working UDP/TCP DNS during backup and after recovery.
- Restored fibre egress, original Windows settings, removed rollback task and
  stopped VM pilot with host network state matching its original snapshot.

The physical Windows run passed, including its local SYSTEM canary rollback.
The counter-verified run recorded 594 forwarded client packets and four inbound
client DNS packets before failure injection. All eight final restoration checks
matched: adapter identity, interface flags, addresses, DNS, NRPT, persistent
routes, active routes and original static IPv4 presence. The temporary scheduled
task was absent after cleanup; the pre-existing SSH service remained unchanged.
The successful result does not establish browser-specific secure-DNS behaviour,
existing-session migration, native-prefix delegation, gigabit capacity, physical
fibre-link outage behaviour or automatic household readiness. SSH configuration
provided before the test is left unchanged; the test does not disable UAC,
change SSH keys/firewall rules or reset the Ethernet adapter.

The subsequent [single-client router-discovery test](WINDOWS-ROUTER-DISCOVERY.md)
now also verifies actual Windows SLAAC, RDNSS and default-router lifetimes using
strictly targeted unicast advertisements and a proved local rollback. It does
not imply that a household-wide overlapping-RA design has been approved.

References: [Microsoft New-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute),
[Microsoft NRPT rules](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule),
[Paramiko host-key policy](https://docs.paramiko.org/en/stable/api/client.html).
