import argparse
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser(description='Request a minimal TL-MR6400 V5 image')
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apn', required=True)
    arguments = parser.parse_args()
    public_key = arguments.public_key.read_text().strip()
    if not public_key.startswith('ssh-rsa ') or any(character in public_key for character in "'\r\n"):
        parser.error('This small-flash Dropbear build requires an RSA public key')
    if not arguments.apn or any(character not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for character in arguments.apn):
        parser.error('Invalid APN')
    arguments.output.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen('https://downloads.openwrt.org/releases/25.12.6/targets/ramips/mt76x8/profiles.json', timeout=30) as response:
        metadata = json.load(response)
    profile = metadata['profiles']['tplink_tl-mr6400-v5']
    defaults = Path(__file__).with_name('99-failsafe-router.sh').read_text()
    defaults = defaults.replace('__SSH_PUBLIC_KEY__', public_key).replace('__CELLULAR_APN__', arguments.apn)
    removed = {'kmod-mt7603', 'wpad-basic-mbedtls', 'odhcp6c', 'odhcpd-ipv6only', 'ppp', 'ppp-mod-pppoe'}
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
