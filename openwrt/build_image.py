import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import urllib.request


def validate_public_key(public_key):
    if not public_key.startswith('ssh-rsa ') or any(character in public_key for character in "'\r\n"):
        raise ValueError('This small-flash Dropbear build requires an RSA public key')
    try:
        data = base64.b64decode(public_key.split()[1], validate=True)
        fields = []
        while data:
            length = struct.unpack('!I', data[:4])[0]
            if length > len(data) - 4:
                raise ValueError
            fields.append(data[4:4 + length])
            data = data[4 + length:]
        if len(fields) != 3 or fields[0] != b'ssh-rsa' or int.from_bytes(fields[2], 'big').bit_length() < 2048:
            raise ValueError
    except (ValueError, IndexError, struct.error) as error:
        raise ValueError('Invalid RSA public key or modulus smaller than 2048 bits') from error


def render_defaults(public_key, apn):
    directory = Path(__file__).parent
    sources = {
        'qmi-watchdog.sh': 'usr/libexec/failsafe-qmi-watchdog',
        'failsafe-qmi.init': 'etc/init.d/failsafe-qmi',
        'cellular-ipv6-probe.sh': 'usr/libexec/failsafe-cellular-ipv6-probe',
        'router-doctor.sh': 'usr/libexec/failsafe-router-doctor',
        'provision-router.sh': 'usr/libexec/failsafe-router-provision',
    }
    content = {target: (directory / source).read_bytes().replace(b'\r\n', b'\n') for source, target in sources.items()}
    manifest = {target: hashlib.sha256(data).hexdigest() for target, data in content.items()}
    content['etc/failsafe-router/files-manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for target, data in sorted(content.items()):
            entry = tarfile.TarInfo(target)
            entry.size = len(data)
            entry.mode = 0o600 if target.endswith('.json') else 0o755
            archive.addfile(entry, io.BytesIO(data))
    payload = gzip.compress(archive_buffer.getvalue(), mtime=0)
    digest = hashlib.sha256(payload).hexdigest()
    encoded = ''.join(f'\\0{value:03o}' for value in payload)
    bootstrap = f'''#!/bin/sh
set -eu
umask 077
mkdir -p /etc/failsafe-router /usr/libexec
printf '%b' '{encoded}' > /tmp/failsafe-router-payload.tar.gz
printf '%s\\n' '{digest}  /tmp/failsafe-router-payload.tar.gz' | sha256sum -c -
gzip -dc /tmp/failsafe-router-payload.tar.gz | tar -xf - -C /
rm -f /tmp/failsafe-router-payload.tar.gz
if [ -f /etc/failsafe-router/provisioned ]; then
    logger -t failsafe-router 'Updated built-in tooling; preserving provisioned network and management configuration'
    exit 0
fi
'''
    defaults = (directory / '99-failsafe-router.sh').read_text()
    defaults = defaults.replace('__SSH_PUBLIC_KEY__', public_key).replace('__CELLULAR_APN__', apn)
    rendered = bootstrap + defaults
    if len(rendered.encode()) > 40960:
        raise ValueError('Embedded defaults exceed the build service size limit')
    return rendered


def main():
    parser = argparse.ArgumentParser(description='Request a minimal TL-MR6400 V5 image')
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apn', required=True)
    arguments = parser.parse_args()
    public_key = arguments.public_key.read_text().strip()
    try:
        validate_public_key(public_key)
    except ValueError as error:
        parser.error(str(error))
    if not arguments.apn or any(character not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for character in arguments.apn):
        parser.error('Invalid APN')
    arguments.output.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen('https://downloads.openwrt.org/releases/25.12.6/targets/ramips/mt76x8/profiles.json', timeout=30) as response:
        metadata = json.load(response)
    profile = metadata['profiles']['tplink_tl-mr6400-v5']
    defaults = render_defaults(public_key, arguments.apn)
    removed = {'kmod-mt7603', 'wpad-basic-mbedtls', 'odhcpd-ipv6only', 'ppp', 'ppp-mod-pppoe'}
    packages = sorted((set(metadata['default_packages']) | set(profile['device_packages']) | {'luci-ssl', 'luci-proto-qmi'}) - removed)
    payload = {
        'version': '25.12.6', 'version_code': metadata['version_code'],
        'target': 'ramips/mt76x8', 'profile': 'tplink_tl-mr6400-v5',
        'packages': packages, 'diff_packages': True, 'defaults': defaults,
        'client': 'failsafe4g/1',
    }
    (arguments.output / 'firstboot-rendered.sh').write_text(defaults, encoding='utf-8', newline='\n')
    (arguments.output / 'build-request.json').write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    request = urllib.request.Request('https://sysupgrade.openwrt.org/api/v1/build', data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    (arguments.output / 'build-response.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
