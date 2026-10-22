# Preserve the working access-point network

The household uses two wired Cudy AP3000 v1 access points running OpenWrt
25.12.6, through an unmanaged PoE switch uplinked to the Freebox. The Freebox
currently provides household routing. Actual management addresses, credentials,
SSID names, mobility domains and private backup reports are intentionally not
published here.

Preserving the existing Wi-Fi service is a hard preparation constraint. Do not
apply UCI changes, reload networking/wireless, restart roaming services, flash
firmware, create an SSID/VLAN or recable these APs as an exploratory test. Their
configuration is not an invitation to "optimize" an already-working network.

## Read-only findings

Both audited APs have:

- A static management LAN using `br-lan`, bridged to the Ethernet uplink.
- Two AP-mode wireless interfaces and two radios reporting up; no configured
  station/mesh wireless uplink.
- IEEE 802.11r enabled on both AP interfaces, with `usteer` running.
- Matching sets of SSIDs, encryption/key material, mobility domains and checked
  fast-transition options across the APs. This compares configuration, not a
  packet-level roaming benchmark.
- Ethernet carrier up with runtime speed reported as `2500F`; this does not
  measure end-to-end throughput or every switch uplink.
- No bridge-VLAN configuration in the audited network UCI configuration.
- No pending UCI changes. Configuration contents/hashes match before and after
  the read-only audit, and a second audit matches the original backups.
- Neither `dnsmasq` nor `odhcpd` running in the service registry. Although stored
  DHCP configuration includes RA/DHCPv6 server options, those fields alone are
  not evidence of a running server. Do not start these daemons or "repair" their
  saved configuration during failover preparation.

The current development PC still observes the Freebox as its IPv6 default router.
This is not proof of all client routing states or a complete passive RA capture.

## Reproducible private backup/audit

`tools/openwrt_ap_audit.py` uses optional Paramiko, a pre-pinned known-hosts file,
and the `FAILSAFE_AP_PASSWORD` environment variable. It never guesses credentials,
accepts unknown SSH keys, replaces existing host-key records or mutates AP
configuration. A changed host identity needs an explicit trust decision before
putting a new key in the supplied pinned file; merely matching an IP/model is
not cryptographic verification of an old SSH identity.

Use `--help` for explicit host, account, known-hosts and new output-path arguments.
The output directory must already be private. On Windows, its owner and allowed
ACL principals are restricted to the current user, Administrators and SYSTEM;
on Unix it must be owned by the current user with no group/other permissions.
Existing reports are never overwritten. Files inherit the private Windows ACL
or are created with Unix mode 0600. A shared Windows Public directory was
explicitly tested and rejected before connecting to an AP.

**The JSON report contains Wi-Fi credentials and other secret configuration.**
Keep it outside Git and cloud/shared folders. Only the sanitized summary should
be printed or shared. The report includes original configuration-file contents,
SHA-256 hashes, UCI/runtime observations and before/after comparison. Required
network/wireless/DHCP file-read failure aborts; absent optional service files are
recorded as absent. These are targeted configuration backups, not complete
sysupgrade images, host-key backups or a rehearsed whole-device restore.

The command set is limited to file reads, UCI reads, ubus read methods, link
inspection and optional bridge-VLAN inspection. It has no apply/restore mode.

## Consequence for rollout design

An unmanaged switch does not provide configurable per-port isolation. Do not
assume that tagged-frame transparency is supported, or treat an untested tagged
network as safe isolation from the household. No managed-switch VLAN migration
can simply be applied to this topology.

Keep current AP service and existing client associations untouched during
preparation. Continue namespace and selected wired-client testing instead of
reloading the household APs to obtain a test SSID. A final controlled-gateway
segment must account for **both** the PoE-switch uplink and clients connected
directly to the Freebox; changing only Wi-Fi routing does not solve wired IPv6.

A physically separate gateway/LAN arrangement could preserve the AP wireless
configuration, but its ports, performance, management addressing, IPv6 policy,
local discovery and rollback must be qualified. It may need hardware or wiring
changes; that is a decision to present to the owner, not authorization to buy
equipment or move cables. Do not quietly route normal fibre through the
100 Mbps cellular router or claim that the current VM provides automatic
host/storage-failure bypass. See the [rollout gates](ROLLOUT-PLAN.md).

Hardware references: [OpenWrt AP3000 v1](https://openwrt.org/toh/hwdata/cudy/cudy_ap3000_v1),
[Cudy AP3000 specifications](https://www.cudy.com/products/ap3000-1-0).
