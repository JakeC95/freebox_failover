# Validation record — 2026-10-21

Version 0.1.0 was validated on the existing Debian 12 ARM64 Freebox Ultra VM.
The initial upstream baseline was verified separately before these changes.

## Passed

- 23 automated checks: outage/recovery decisions, unknown API grace, backup health
  thresholds, invalid config, token privacy/atomic replacement, zero track ID,
  malformed API replies, secret-free errors, session renewal, MAC verification,
  pending authorization resume, stale-status detection, rejection of primary-route
  fallback during backup probes, and legacy USB ping,
  API-error, ARP restoration and IPv6 packet behaviour.
- Isolated client/VM/primary/backup Linux namespaces: marked backup probes,
  unchanged primary routes, actual masqueraded HTTP traffic, UDP/TCP Freebox DNS
  redirection and translated return traffic, full API-driven ARP takeover,
  recovery, SIGTERM cleanup and saved-state crash recovery.
- Legacy USB nftables configuration applied twice in its own namespace while
  preserving an unrelated table; interfaces need not exist at rule load time.
- New Debian cloud-init template validated with `cloud-init schema`.
- Source distribution and wheel built successfully; native RPM build was not run.
- Source installer deployed to `/opt/freebox-failover`, preserving the existing
  config byte-for-byte and creating a completed, root-only rollback backup.
- Existing Freebox token authenticated successfully without another registration.
- Real systemd watchdog recovery: the monitor was deliberately paused with
  SIGSTOP; watchdog termination and automatic restart produced a new healthy PID.
  Temporary watchdog settings were removed and the normal 90-second setting restored.

The initial completed pre-upgrade backup is
`/var/backups/freebox-failover/20261021T171047-2745/` on the VM.
Validation harnesses used during development are outside the checkout, in the
local temporary directory and `/tmp` on the VM. They are not installed services.
The GitHub fork is `JakeC95/freebox_failover`.

## Live review before publication

At 2026-10-21 17:26 UTC, the deployed service had run for over eight minutes
since its 17:17:15 UTC startup, with zero automatic restarts and no warning/error
journal entries in the last ten minutes. The heartbeat was fresh, WAN was `up`,
the API error field was empty, and takeover remained disabled. SHA-256 hashes of
all four deployed Python modules matched the source being prepared for publication.
The normal 90-second watchdog was configured, no failover policy rule or nftables
table remained, and the default route still used the Freebox.

## Scope

Production fibre was not interrupted. Runtime takeover remains disabled, Freebox
WAN reports `up`, and the primary default route still points to `192.168.1.254`.
The physical 4G router, cellular service, real DNS resolver operation under an
outage, production client ARP behaviour and IPv6 remain to be verified. Legacy
USB hardware forwarding and Fedora/RPM installation have not been exercised.
