# Operations — Freebox Ultra

Household activation requires the separate [rollout approval gates](docs/ROLLOUT-PLAN.md).
The read-only `tools/rollout_preflight.py` checks preparation safety, not production
readiness; a passing report never enables takeover or authorizes network changes.

## Inspect the running service

```sh
sudo systemctl status freebox_ethernet --no-pager
sudo python3 /opt/freebox-failover/freebox_ethernet.py --status
sudo python3 /opt/freebox-failover/freebox_ethernet.py --doctor
sudo journalctl -u freebox_ethernet -n 40 --no-pager
```

`--status` makes no API calls and exits nonzero if monitoring has stopped or its
report is stale. It reports mode, WAN state, takeover state, decision reason,
backup readiness, most recent probe latency, safe API error codes and uptime.
The report is written atomically under `/run`, which is volatile storage.
`--doctor` checks required tools, interface/addressing, token readability and
permissions, configuration blockers and the service heartbeat. `monitor_ready`
means dependencies/configuration permit monitoring; use `--check` to verify API
access and `--check-backup` to verify the backup path separately.

The systemd watchdog expects progress from the **main loop** every 90 seconds.
A stalled process is terminated, its cleanup command runs, and systemd restarts
it. Normal logs record transitions and error changes instead of every poll.
Logs are volatile on this VM and disappear after a reboot.
Automatic restarts retry every 30 seconds without a start-count lockout, so a
temporary startup failure cannot permanently disable monitoring. Repeated
failures remain visible in the journal and `NRestarts` service property.

## Timing and stability

The Freebox API is checked every two seconds by default. Backup TCP probes run
every 15 seconds while fibre is up and every two seconds during an outage or
active takeover. Two successful samples establish backup readiness; three failed
samples remove it. Samples may each take up to the number of configured targets
times `probe_timeout`, so observed detection time includes network timeouts.

Explicit WAN outage must persist for `down = 10` seconds before takeover; recovery
must persist for `up = 20` seconds. An unknown API state never initiates takeover.
With the default `unknown_policy = release`, an active healthy backup continues
for `unknown_grace = 15` seconds of API uncertainty, then ownership returns to
the Freebox. The household deployment now explicitly selects
`unknown_policy = hold_backup`: an already active, healthy backup remains in use
until the Freebox confirms recovery for the full `up` interval. This avoids
abandoning working LTE solely because the management API is unavailable, but
can extend cellular data use if the API stays unavailable after fibre recovers.
Status reports `api_unknown_holding_backup` and the journal warns when this
condition starts. Neither policy initiates takeover from API uncertainty alone.
Confirmed backup failure releases takeover immediately under both policies.
These decisions use monotonic time.

For an unattended period, check the SIM's remaining data/validity with the
operator. No external failure notification is configured; the service's status
and journal are the local diagnostics. To disable takeover and restore the
Freebox path from the VM, use:

```sh
sudo python3 /opt/freebox-failover/tools/household_rollback.py
```

That command leaves monitoring running with takeover disabled until explicitly
re-enabled. It requires the VM and its host to remain reachable.

`--check-backup` is a one-shot route/probe diagnostic, not the consecutive-sample
readiness decision. Stop the monitoring service before running it so it can
acquire the exclusive runtime lock.

## Install or upgrade

The source installer targets `/opt/freebox-failover`. Required Debian packages:
`python3-requests python3-scapy nftables iproute2 libpcap0.8`. It does not run pip
or apt automatically. Legacy USB additionally needs `ping3`; journal output
requires `python3-systemd`, but neither is needed by Ethernet mode.

1. Keep the new checkout or release in a separate directory. Set takeover
   `enabled = false` and stop the Ethernet service before upgrading an armed VM.
2. Run `sudo bash install-freebox-ultra.sh` from the new source directory.
3. Confirm `--status`, `--doctor` and `--check`. Review the configuration blockers.

Before replacing code, the installer saves source files, live Ethernet config,
unit and overrides in `/var/backups/freebox-failover/<timestamp>-<pid>/`, accessible
only to root. The live token is reused and is never printed or copied into the
checkout. It preserves the live config and refuses to upgrade an armed config.
Completed backups contain a `COMPLETE` marker; ignore incomplete attempts.

The supplied service works with package-installed scripts under `/usr/bin`.
The source installer adds `/etc/systemd/system/freebox_ethernet.service.d/source.conf`
to select the `/opt` checkout. Existing config timing options remain compatible.
Python wheels ship configuration/unit templates under `share/freebox-failover`;
they do not overwrite `/etc` or enable services. For a pip installation, choose
the actual installed script path in the service override. RPM packaging installs
the native config/unit locations without running pip from package hooks.

## Roll back

Stop the service first. A backup's `source.tar.gz` contains the previous checkout;
inspect it with `sudo tar -tzf <backup>/source.tar.gz`, then restore it using
`sudo tar -xzf <backup>/source.tar.gz -C /opt/freebox-failover`.
Restore the saved `etc/freebox_ethernet.conf` and `etc/systemd/system` files from
that same backup. If the backup has no `source.conf`, remove only the installer
override `/etc/systemd/system/freebox_ethernet.service.d/source.conf` before
restoring the old unit. Run `sudo systemctl daemon-reload` and start the service.
Keep takeover disabled while checking the restored version.

For operational shutdown:

```sh
sudo systemctl disable --now freebox_ethernet
sudo python3 /opt/freebox-failover/freebox_ethernet.py --cleanup
```

## Registration

```sh
sudo python3 /opt/freebox-failover/freebox_failover_register.py -c /etc/freebox_ethernet.conf --check-existing
```

Omit `--check-existing` only when registration is needed. A saved pending request
resumes polling instead of creating another app. Existing denied/invalid tokens
are reported explicitly rather than silently replaced. Keep the token mode `600`;
do not copy its contents into diagnostics or Git. Registration returns failure
exit codes and closes its API session on exit.

Authentication follows the [Freebox OS login API](https://dev.freebox.fr/sdk/os/login/).
Watchdog behaviour follows [systemd service supervision](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
