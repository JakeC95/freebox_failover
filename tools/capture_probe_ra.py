#!/usr/bin/env python3
"""Bounded capture of one probe router's RAs, not household traffic."""

import argparse
import ipaddress
import json
from pathlib import Path
import re

from scapy.all import Ether, IPv6, ICMPv6ND_RA, sniff


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--source-mac', required=True)
    parser.add_argument('--target-mac', required=True)
    parser.add_argument('--target-ipv6', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--seconds', type=int, default=180)
    arguments = parser.parse_args()
    for mac in (arguments.source_mac, arguments.target_mac):
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
            raise ValueError('Explicit lowercase Ethernet addresses required')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', arguments.interface):
        raise ValueError('Invalid capture interface')
    peer = ipaddress.IPv6Address(arguments.target_ipv6)
    if not peer.is_link_local or not 1 <= arguments.seconds <= 240:
        raise ValueError('A link-local peer and bounded capture are required')
    with Path(arguments.output).open('w', encoding='utf-8') as output:
        def ready():
            output.write(json.dumps({'ready': True}) + '\n')
            output.flush()

        def record(packet):
            confined = (packet[Ether].dst == arguments.target_mac and
                        ipaddress.IPv6Address(packet[IPv6].dst) == peer and
                        packet[IPv6].hlim == 255)
            output.write(json.dumps({'confined': confined,
                                     'router_lifetime': packet[ICMPv6ND_RA].routerlifetime,
                                     'hop_limit': packet[IPv6].hlim}) + '\n')
            output.flush()

        sniff(iface=arguments.interface,
              filter=f'ether src {arguments.source_mac} and icmp6 and ip6[40] == 134',
              prn=record, store=False, timeout=arguments.seconds, started_callback=ready)


if __name__ == '__main__':
    main()
