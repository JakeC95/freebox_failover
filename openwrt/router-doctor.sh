#!/bin/sh
set -e
. /usr/share/libubox/jshn.sh

board=$(ubus call system board)
wan=$(ubus call network.interface.wan status)
memory=$(awk '/MemAvailable:/ { print $2 }' /proc/meminfo)
space=$(df -k /overlay | awk 'NR == 2 { print $4 }')
ipv4=0
ipv6=0
ipv6_route=0
[ -z "$(jsonfilter -s "$wan" -e '@["ipv4-address"][0].address')" ] || ipv4=1
if jsonfilter -s "$wan" -e '@["ipv6-address"][*].address' | grep -q '^[23]'; then ipv6=1; fi
if ip -6 route show default dev wwan0 | grep -q '^default'; then ipv6_route=1; fi
nat6=0
[ ! -f "/lib/modules/$(uname -r)/nft_masq.ko" ] || nat6=1
dhcp6_client=0
if command -v odhcp6c >/dev/null; then dhcp6_client=1; fi
lan_disabled=0
[ "$(cat /proc/sys/net/ipv6/conf/br-lan/disable_ipv6)" != 1 ] || lan_disabled=1

json_init
json_add_string model "$(jsonfilter -s "$board" -e '@.model')"
json_add_string openwrt "$(jsonfilter -s "$board" -e '@.release.version')"
json_add_string cellular_pdp "$(uci -q get network.wan.pdptype)"
json_add_boolean ipv4_address "$ipv4"
json_add_boolean public_cellular_ipv6 "$ipv6"
json_add_boolean cellular_ipv6_default_route "$ipv6_route"
json_add_boolean nat6_module_available "$nat6"
json_add_boolean dhcpv6_client_available "$dhcp6_client"
json_add_boolean lan_ipv6_disabled "$lan_disabled"
json_add_boolean lan_dhcp_disabled "$(uci -q get dhcp.lan.ignore)"
json_add_string lan_ra "$(uci -q get dhcp.lan.ra)"
json_add_int available_memory_kb "${memory:-0}"
json_add_int free_overlay_kb "${space:-0}"
json_add_boolean household_ipv6_failover_implemented 0
json_dump
