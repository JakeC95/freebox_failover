#!/bin/bash
set -euo pipefail

if [[ $(id -u) != 0 ]]; then
    echo "Run with sudo bash install-freebox-ultra.sh" >&2
    exit 1
fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
destination=/opt/freebox-failover
config_file=/etc/freebox_ethernet.conf
unit_file=/etc/systemd/system/freebox_ethernet.service
dropin_dir=/etc/systemd/system/freebox_ethernet.service.d

for dependency in python3 ip nft systemctl; do
    command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 1; }
done
python3 -c 'import requests, scapy.all'
for name in freebox_api.py freebox_ethernet.py freebox_failover.py freebox_failover_register.py; do
    python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$source_dir/$name"
done
for name in README.md ETHERNET.md OPERATIONS.md freebox_ethernet.conf freebox_ethernet.service; do
    [[ -f "$source_dir/$name" ]] || { echo "Incomplete checkout: $name is missing" >&2; exit 1; }
done
if systemctl is-active --quiet freebox_failover.service; then
    echo "Stop the legacy USB service before installing Ethernet mode." >&2
    exit 1
fi
if [[ -f "$config_file" ]]; then
    python3 - "$config_file" <<'PY'
import configparser
import sys
config = configparser.ConfigParser(interpolation=None)
config.read(sys.argv[1])
if config.getboolean('ethernet', 'enabled', fallback=False):
    raise SystemExit('Stop takeover and set enabled=false before upgrading.')
PY
fi

backup_dir="/var/backups/freebox-failover/$(date -u +%Y%m%dT%H%M%S)-$$"
install -d -m 700 "$backup_dir"
if [[ -d "$destination" ]]; then
    tar -C "$destination" --exclude=.git --exclude=.venv --exclude=__pycache__ \
        --exclude=build --exclude=dist -czf "$backup_dir/source.tar.gz" .
fi
for name in "$config_file" "$unit_file" "$dropin_dir"; do
    if [[ -e "$name" ]]; then
        relative_name=${name#/}
        install -d -m 700 "$backup_dir/$(dirname -- "$relative_name")"
        cp -a -- "$name" "$backup_dir/$relative_name"
    fi
done
printf 'Backup complete\n' >"$backup_dir/COMPLETE"
systemctl stop freebox_ethernet.service 2>/dev/null || {
    if systemctl cat freebox_ethernet.service >/dev/null 2>&1; then exit 1; fi
}
install -d -m 755 "$destination" "$dropin_dir"
for name in freebox_api.py freebox_ethernet.py freebox_failover.py freebox_failover_register.py \
            README.md ETHERNET.md OPERATIONS.md VALIDATION.md LICENSE pyproject.toml requirements.txt MANIFEST.in \
            cloud-init-freebox-ultra.yaml cloud-init-user-data.yaml install-freebox-ultra.sh \
            freebox-failover.spec freebox_failover.conf freebox_failover.service \
            freebox_ethernet.conf freebox_ethernet.service; do
    if [[ "$source_dir" != "$destination" ]]; then
        install -m 644 "$source_dir/$name" "$destination/$name"
    fi
done
if [[ "$source_dir" != "$destination" ]]; then
    install -d -m 755 "$destination/docs" "$destination/systemd"
    install -m 644 "$source_dir/docs/upstream-README.fr.md" "$destination/docs/"
    install -m 644 "$source_dir/systemd/freebox_failover.env" "$destination/systemd/"
fi
if [[ ! -e "$config_file" ]]; then
    install -m 600 "$source_dir/freebox_ethernet.conf" "$config_file"
fi
install -m 644 "$source_dir/freebox_ethernet.service" "$unit_file"
cat >"$dropin_dir/source.conf" <<'UNIT'
[Service]
Environment=FAILOVER_SCRIPT=/opt/freebox-failover/freebox_ethernet.py
UNIT
chmod 644 "$dropin_dir/source.conf"
systemctl daemon-reload
systemd-analyze verify "$unit_file"
systemctl enable --now freebox_ethernet.service
printf 'Installed. Configuration preserved. Backup: %s\n' "$backup_dir"
python3 "$destination/freebox_ethernet.py" --status
