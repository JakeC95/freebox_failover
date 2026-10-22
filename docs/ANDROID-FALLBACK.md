# Targeted Android IPv4 fallback observation

`tools/android_ipv4_fallback.py` performs a bounded, per-MAC experiment on the
existing OpenWrt access points. It does not modify UCI, reload Wi-Fi, change
roaming, advertise routes, or enable household takeover. SSH host keys must be
pinned. Supply the AP password in `FAILSAFE_AP_PASSWORD`; reports must be new
files in an existing private directory. Do not commit household reports.

Without `--run`, it discovers the selected client's association and validates
the proposed rules using `nft -c`. `--mode observe --run` installs counters only.
`--mode drop --run --confirm-cellular-off` silently drops only the selected
source MAC's packets to public IPv6 destinations (`2000::/3`) on AP ingress.
IPv4, local IPv6 discovery and Freebox router advertisements remain unchanged.
Supply both APs using repeated `--host` arguments to accommodate roaming.

Each AP starts its own detached worker which installs and expires its rules. The
duration is limited to 5–180 seconds. The controller checks independent expiry,
removes its own table on errors and compares the original ruleset and hashes
of network, wireless and DHCP configuration. If the controller loses access,
the AP-local expiry still removes the temporary table. An AP reboot also
discards the nonpersistent rules. This does not protect against a hung AP OS.

## Manual acceptance

1. Keep the selected phone on its existing home Wi-Fi and turn mobile data off.
   Record any VPN and Android Private DNS settings without changing them first.
2. On native fibre, open important apps and a fresh browser tab. Record baseline
   delays and the `ip` field at `https://www.cloudflare.com/cdn-cgi/trace`.
   A browser can already choose IPv4 on healthy dual-stack Wi-Fi; that alone
   does not establish whether the phone has working IPv6.
3. Run a counter-only canary and verify independent expiry on both APs before
   starting a dropping test. Run the dropping test for about 120 seconds.
4. During that window, repeat browsing, messaging and streaming. Note errors,
   delays, Wi-Fi validation warnings and whether existing sessions recover.
   Request `https://ipv4.icanhazip.com` and `https://ipv6.icanhazip.com` to compare
   explicit address families. Site availability and caches can affect results.
5. After automatic expiry, repeat the baseline. Confirm ruleset/configuration
   restoration, and restore the phone's mobile-data setting when finished.

Counters demonstrate packet matches, not which Android application generated
them. User observations are required; an AP cannot establish an app's success.
No test result is implied merely by preparing or running the filter.

**This first experiment leaves IPv4 on fibre.** It tests application response
to silent IPv6 loss with the real household DNS/RA configuration. It does not
prove LTE routing, backup DNS, outage detection, carrier reachability, IPv6
withdrawal, or a full automatic failover. A separate phone-only LTE data-path
test is still required before drawing conclusions about those components.

## Phone-only LTE data path

`tools/android_lte_pilot.py` provides that separate experiment without changing
the phone's static IP settings or spoofing the Freebox gateway. Supply pinned
AP/router host keys, the router SSH key, confirmed client IP/MAC, primary and
backup MACs, and the LAN prefix. Its default is validation only; activation
requires `--run --confirm-cellular-off`. Use a new private `--report` file.

On each AP, a temporary ingress table matches only the selected phone's source
MAC/IP and frames addressed to the Freebox MAC. Public IPv4 traffic and IPv4
DNS traffic are redirected by changing only the destination Ethernet address
to the LTE router's real MAC. Other local IPv4 traffic remains untouched.
Public IPv6 and IPv6 DNS from the selected phone are silently dropped; local
IPv6 discovery remains available. Wi-Fi configuration, DHCP and RA are unchanged.

On the LTE router, temporary source-IP/MAC-scoped DNAT sends the phone's IPv4
DNS flows to its existing DNS proxy; conntrack reverses that translation in
replies. Existing firewall forwarding/NAT policies still apply. Additional
non-verdict counters observe the phone's forwarding in both directions on
`br-lan`/`wwan0`. These counters can underestimate offloaded traffic and do not
identify applications or prove their success. The DNS NAT counter counts new
matching flows, not every request.

The script verifies an exclusively cellular default route, checks rule syntax,
and requires working UDP/TCP backup DNS and verified IPv4 HTTPS before steering.
The backup must pass these checks repeatedly for at least three minutes before
any phone rules are installed (`--stability-seconds`, 180–300 seconds).
It repeats backup health checks during the experiment and restores normal
forwarding if the cellular session goes down/restarts or DNS/HTTPS fails.
This limits rather than eliminates the interruption: a failed health probe can
take several seconds to time out. A completed control/cleanup run is not an
application acceptance result; the user's observations remain required.
The script also rehearses the router's independent expiry using a harmless temporary table
before activation. Each device runs a detached installer/expiry worker. AP
steering expires after the chosen 30–180 second duration; router DNS rules
expire 30 seconds later, so normal AP forwarding returns first. The controller
also attempts cleanup on failure and checks configuration hashes and original
rulesets. No persistent configuration or household takeover is enabled.

During the window, compare a fresh IPv4 address-check page with an independently
measured LTE public IP, use important applications, and report delays/errors.
Expect some existing sessions to reconnect when public source addresses change.
After expiry, confirm browsing works again on fibre. A successful manual data
path test does not qualify automatic detection timing, a physical fibre cut,
all household devices, or the future deployment SIM. A zero IPv6 drop counter
still does not establish a witnessed IPv6-to-IPv4 application transition.

## Automatic takeover/recovery rehearsal

Add `--automatic --seconds 180` and pinned `--vm-host`, `--vm-key`,
`--vm-known-hosts` arguments to the LTE pilot. `--vm-uplink` must identify a
checked unused LAN address outside DHCP/reservations; the VM pilot also ARP
checks it before use. The existing three-minute cellular stability gate and
AP/router expiry workers remain mandatory.

The VM runs the existing `dual_stack_pilot.py` in bounded namespaces, with
separate pinned fibre/cellular DNS and HTTPS probes. A primary-path fault is
injected only inside that namespace. At the same time, temporary AP sets
simulate Internet loss only for the selected phone. All other clients retain
their real fibre connection. No multicast RA, gateway identity takeover,
radio reload or physical fibre interruption is used.

The controller does not select LTE merely because a timer expired. It waits
for the VM pilot's three-failure/two-healthy-backup decision, then updates
phone-only AP sets to steer IPv4/DNS through the real cellular router. IPv6
remains blocked. After a 60-second observation window the injected fault is
cleared; AP steering remains on LTE until the VM reports three healthy primary
samples and permits recovery. Exactly one takeover and recovery are required.
Detection/recovery delays, health samples, transitions and packet counters are
written to the private report. Existing application acceptance still requires
the user's observations.

The AP tables initially have empty selector sets, so arming them does not
reroute traffic. Updates only change sets in existing tables, atomically per
AP; they cannot recreate a table after its independent expiry. The router
expires 30 seconds after AP steering. The VM has an independent 300-second
process timeout, and normal cleanup explicitly checks its host network state
against baseline. The controller itself is a temporary test harness, not an
always-on dependency or the household production daemon.

This verifies a **scoped synthetic outage rehearsal**, not a real ISP outage,
the production Freebox API decision path, household ARP takeover, or permanent
IPv6/DNS behavior for every household device. Never interpret the report as
permission for a network-wide rollout.
