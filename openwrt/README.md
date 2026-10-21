# TL-MR6400 EU V5.0 Ethernet backup

These tools target **TP-Link TL-MR6400 EU V5.0**, not V4, V5.2, V5.3 or other
revisions. The router provides an independent LTE gateway at `192.168.1.253`;
the Freebox remains the household gateway and DHCP server. Connect LAN1–LAN3,
not LAN4/WAN. Never enable the router's DHCP server on the Freebox LAN.

## Image and recovery

`build_image.py` requests a lean OpenWrt 25.12.6 image from the official
Attended Sysupgrade service. It includes QMI, LuCI, HTTPS and the optional IPv6
DHCP client, but excludes Wi-Fi, PPP and the IPv6 DHCP/RA server. The build
also embeds the recovery service, diagnostics, provisioning and bounded IPv6
capability probe, with a SHA-256 manifest. The build service receives the public SSH
key, APN and first-boot script. **Never put passwords, private keys or SIM PINs
in that script or the build request.** Store all generated artifacts outside
the checkout in a restricted directory.

Use an RSA key (3072 bits recommended). This small-flash Dropbear build does
not support Ed25519 authentication. Supplying only an Ed25519 key while
disabling password login locks out normal SSH access.

The embedded installer uses only shell `printf`, gzip, tar and sha256sum;
the lean image does not contain a `base64` command. Its compressed payload is
deterministic, hash-checked before extraction and bounded by the service's
40 KiB defaults limit. An existing `/etc/failsafe-router/provisioned` marker
preserves initialized WAN, firewall, password, SSH and HTTPS configuration on
upgrade instead of re-running fresh-install defaults. Include the marker in
the configuration backup and verify the preserve branch before flashing.

```text
python openwrt/build_image.py --public-key PATH_TO_RSA_PUBLIC_KEY --output PRIVATE_DIRECTORY --apn OPERATOR_APN
```

Download the successful build's `tftp-recovery` image; verify its size and
SHA-256 against the build response. Independently check the V5 hardware header,
absence of a bootloader payload and embedded first-boot script before flashing.
Do not use the OEM web updater for first installation.

`tftp_once.py` serves only `tp_recovery.bin` in octet mode to one specified
client, and refuses an image whose SHA-256 does not match. It supports the
bootloader's default 512-byte blocks and optional TFTP negotiation. A completed
transfer is **not** proof that flashing or booting has completed.

The documented recovery addresses are server `192.168.0.225/24` and client
`192.168.0.2`. Use a direct isolated Ethernet connection and narrowly scoped
temporary firewall rules for UDP 69 and the selected transfer port. Hold Reset
while powering on, release after at least eight seconds, then leave power and
Ethernet untouched for at least five minutes. Keep OEM recovery and configuration
backups available. Do not overwrite bootloader or calibration partitions.

## Provisioning

The first-boot script leaves cellular autostart off, SSH key-only, DHCP/RA off,
and web management inaccessible from the LAN until private provisioning.
Immediately back up the boot, config and factory MTD partitions over SSH and
compare local and remote hashes. Keep those device-specific backups private.

Set a unique strong root password privately before running
`provision-router.sh` over SSH. It disables router IPv6, keeps SSH key-only,
enables LAN-only HTTPS and brings up the QMI connection with carrier DNS.
IPv4 DHCP on the **QMI WAN** must also be disabled (`network.wan.dhcp=0`), as
documented for this model; obtain addresses directly from QMI instead.

The supplied SIM currently uses APN `www.inwi.ma`, CHAP with empty credentials,
IPv4 and roaming. The live configuration retains modem autoconnect. Do not
assume this APN/authentication works with a replacement SIM: obtain its
operator's settings and check PIN status without guessing a PIN. There is no
radio-band lock. Automatic roaming showed stale addressing and dropped sessions
after reconnects with this Moroccan SIM. A diagnostic selection of Orange
(`network.wan.plmn=20801`) passed a subsequent WAN reconnect and remains selected
for this SIM while acceptance testing continues. This is not a requirement to
buy an Orange SIM. For a replacement SIM, set `network.wan.plmn=0` to restore
automatic operator selection and retest with the correct APN/authentication.

HTTPS uses an EC P-256 certificate. The embedded px5g version accepts separate
`-addext` arguments, not a comma-separated SAN list, and incorrectly encoded
the tested IPv4 SAN. The live device therefore uses a separately generated
OpenSSL certificate with correct DNS and IPv4 SANs, verified with normal TLS
hostname checking and a device-specific trust file. No global TLS weakening or
OS trust-store change is needed. The fallback in the provisioning script makes
a hostname-only certificate, not an IP-valid certificate.

`qmi-watchdog.sh` checks the active netifd WDS client, rather than allocating
an unrelated client and trusting its data-status response. When a stable WAN
has stale addressing or loses its QMI session, three consecutive failures
request `ifup wan`, at most once per 180 seconds. Pending/new sessions and
administratively disabled interfaces are not interrupted. It does not guess
PINs, reboot hardware, flash firmware or activate Freebox failover.

Install it as `/usr/libexec/failsafe-qmi-watchdog` and `failsafe-qmi.init` as
`/etc/init.d/failsafe-qmi`, both executable. Enable/start the procd service.
Include both paths, `/etc/sysctl.d/90-failsafe-router.conf` and the enabled
`/etc/rc.d/S95failsafe-qmi` and `/etc/rc.d/K15failsafe-qmi` symlinks in
`/etc/sysupgrade.conf`; otherwise a later sysupgrade can omit custom code.
`--check` exits 0 for matching addresses, 10 for drift, 11 for a lost session,
12 for an unusable response, 20 when intentionally skipped and 21 when down.

## Acceptance boundary

The initial 25.12.6 recovery image had SHA-256
`aa2aa71e7fac618dc32809383bd1c3a93e6e5c6ce76aae2ac2a1b09cf83e45f0`.
Its embedded defaults predate the later DHCP/PDP refinements in this directory;
those refinements are applied in the live configuration over SSH. Do not assume
rebuilding this directory reproduces that older image byte for byte.

The subsequent integrated-tools sysupgrade image has SHA-256
`3685bdb93d6d451fe1d167d248135bc0aa5676e3f604d72735966fee1eaadda9`.
The [dual-stack development record](../docs/DUAL-STACK-DESIGN.md) distinguishes
its added capabilities from household IPv6 failover, which is not implemented.

Observed checks on 2026-10-21 UTC (2026-10-22 local time):

- Verified backups of boot/config/factory MTD partitions and private configuration.
- RSA key-only SSH; private root login over verified TLS 1.3 with EC P-256.
- Only SSH, DNS and HTTPS listening on the LAN; no HTTP, Telnet, FTP or UPnP.
- DHCP/RA disabled; router IPv6 disabled; only cellular default routing.
- Carrier DNS, HTTPS and a 1 MiB download pass after cold boot.
- With Orange selected for the current roaming SIM, WAN reconnect and warm
  reboot also pass subsequent verified HTTPS checks.
- Nine TFTP checks and twelve watchdog state/debounce/cooldown checks pass.

After reconnecting the router to the Freebox LAN, marked VM forwarding/NAT
checks also pass: three health samples, UDP/TCP DNS through the backup router,
verified TLS 1.3 and a 1 MiB download in 1.84 seconds (about 4.56 Mbps including
setup, not a throughput benchmark). Backup and primary egress are distinct.
Public UDP resolvers remain unreachable through this roaming SIM, so use the
router's carrier-DNS proxy rather than hard-coding public DNS.

The temporary policy rule, routing table and nftables table are removed after
the probe; normal fibre routing and monitor-only service are restored. The PC's
temporary USB addressing/firewall changes are also removed. Household failover
acceptance remains pending the [Freebox IPv6 design](../docs/FREEBOX-IPV6.md)
and separate user approval.

Successful DNS, HTTPS and downloads on the router prove cellular egress, not
household failover. Repeat checks after cold boot, warm reboot and a WAN
reconnect; inspect the actual modem addresses, routes and logs. A previous warm
restart left stale addressing, so a single successful connection is insufficient.
The QMI driver also emits a SIM-status parsing warning before its successful
PIN-disabled fallback; do not describe these logs as warning-free.

Before arming failover, reconnect to the Freebox LAN, remove PC staging routes,
repeat explicitly marked VM DNS/HTTPS/download tests, and resolve the Freebox
LAN IPv6 bypass. Leave the failover service monitor-only until those checks and
the user's separate approval for controlled failover/failback tests.

References: [OpenWrt device instructions](https://openwrt.org/toh/tp-link/tl-mr6400_v5),
[small-flash Dropbear defaults](https://github.com/openwrt/openwrt/blob/openwrt-25.12/package/network/services/dropbear/Config.in),
[QMI client-ID explanation](https://github.com/openwrt/uqmi/issues/7).
