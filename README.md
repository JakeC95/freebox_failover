# Freebox Ultra Failover

Automatic IPv4 backup through an Ethernet 4G router, running in a small Linux VM
on a Freebox Ultra. This adaptation is based on
[Laurent Vivier's freebox_failover](https://github.com/vivier/freebox_failover),
starting at `f22a10d032d99e5244492a704412ec937304c9b1`. His gateway takeover
approach and GPL-3.0-or-later license are retained. Version: **0.1.0**.
The adaptation's home is [JakeC95/freebox_failover](https://github.com/JakeC95/freebox_failover).

The current deployment is Debian 12 ARM64, one vCPU, 1 GiB RAM and the existing
USB storage. The VM is `192.168.1.70`; the Freebox is `192.168.1.254`. Normal fibre
traffic goes directly through the Freebox. The VM forwards traffic only during
an armed and confirmed outage with a working backup.

## What is implemented

- Ethernet backup over the VM's existing LAN interface, with dedicated policy
  routes, scoped nftables NAT and Freebox DNS redirection.
- Probe traffic pinned to the backup, separate success/failure thresholds, and
  reduced probing while fibre is healthy.
- Monotonic outage/recovery timers and a bounded grace period for API errors.
- Shared, persistent HTTP connections; session renewal; validated API responses;
  atomic token writes with private permissions; registration safe to import.
- Gateway restoration on shutdown, crash-state recovery and systemd supervision
  of a stalled main loop. Runtime state and health reports live in RAM.
- Read-only diagnostics, stale-status detection, a configuration-preserving
  installer, upgrade backups and a fresh Debian cloud-init template.
- Legacy USB support with corrected ping results, explicit backup-interface
  probes, safe API error handling, stoppable packet capture, proper IPv6 neighbour
  options/hop limits and working service environment overrides.

## Start here

Read [Ethernet setup](ETHERNET.md) for router wiring, addressing and the IPv6
requirement. Read [operations](OPERATIONS.md) for health checks, upgrades and
rollback. The repository's configuration matches this VM and defaults to
`enabled = false`; adapt it before using another installation.

On an already prepared Debian VM, from a checkout:

```sh
sudo bash install-freebox-ultra.sh
sudo python3 /opt/freebox-failover/freebox_ethernet.py --doctor
sudo python3 /opt/freebox-failover/freebox_ethernet.py --status
```

The installer checks dependencies, preserves `/etc/freebox_ethernet.conf`, and
starts monitoring. Fresh VM provisioning uses `cloud-init-freebox-ultra.yaml`;
replace its SSH public-key placeholder before use. The old
`cloud-init-user-data.yaml` is for the historical Fedora/USB arrangement.

## Current limits

Automatic takeover stays disabled until the 4G router and the LAN IPv6 plan are
verified. This release's Ethernet mode supports IPv4 only. Its ARP takeover is
best effort; existing connections can reset when the public IP changes. A VM
hosted by the Freebox cannot protect against the Freebox losing power or crashing.
The cellular connection and production client behaviour still need physical
testing when the router is available.
Primary outage detection currently follows the Freebox WAN API state. An ISP
routing/DNS failure while that state remains `up` does not trigger takeover.

Future work should start with validated IPv6 backup support and primary Internet
path checks, then modem-specific status and optional notifications. A dashboard or remote control API is not
required to run the daemon.

The [original French README](docs/upstream-README.fr.md) is preserved for provenance.
See [validation results](VALIDATION.md) for what has been exercised on the VM.
