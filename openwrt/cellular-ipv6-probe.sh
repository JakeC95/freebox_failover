#!/bin/sh
set -eu

restore_network() {
    directory="$1"
    case "$directory" in
        /tmp/failsafe-ipv6-probe.*) ;;
        *) exit 2 ;;
    esac
    [ -f "$directory/armed" ] || return 0
    mkdir "$directory/restoring" 2>/dev/null || return 0
    if ! cp "$directory/network" /etc/config/network || ! ifup wan || ! /etc/init.d/failsafe-qmi start; then
        rmdir "$directory/restoring"
        return 1
    fi
    rm -f "$directory/armed"
    rmdir "$directory/restoring"
    rmdir /var/lock/failsafe-ipv6-probe 2>/dev/null || true
    logger -t failsafe-ipv6-probe 'Original cellular configuration restored'
}

case "${1:-}" in
    --rollback-guard)
        sleep 240
        restore_network "$2"
        exit 0
        ;;
    --restore-now)
        restore_network "$2"
        exit 0
        ;;
    --run) ;;
    *) echo 'Usage: cellular-ipv6-probe.sh --run (temporarily reconnects standby LTE; always restores IPv4 configuration)'; exit 2 ;;
esac

[ "$(id -u)" = 0 ]
[ "$(ubus call system board | jsonfilter -e '@.board_name')" = tplink,tl-mr6400-v5 ]
[ "$(uci get network.wan.proto)" = qmi ]
[ "$(uci get network.wan.device)" = /dev/cdc-wdm0 ]
[ "$(uci get network.wan.pdptype)" = ip ]
[ "$(uci get dhcp.lan.ignore)" = 1 ]
[ "$(uci get dhcp.lan.ra)" = disabled ]
[ "$(cat /proc/sys/net/ipv6/conf/br-lan/disable_ipv6)" = 1 ]
[ -z "$(uci changes network)" ]
[ -x /etc/init.d/failsafe-qmi ]
[ -f /usr/libexec/failsafe-cellular-ipv6-probe ]

umask 077
mkdir /var/lock/failsafe-ipv6-probe 2>/dev/null || { echo 'Another probe holds the lock'; exit 1; }
directory=$(mktemp -d /tmp/failsafe-ipv6-probe.XXXXXX)
cp /etc/config/network "$directory/network"
touch "$directory/armed"
finish() {
    /usr/libexec/failsafe-cellular-ipv6-probe --restore-now "$directory"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
(
    trap '' HUP
    exec /usr/libexec/failsafe-cellular-ipv6-probe --rollback-guard "$directory"
) > "$directory/guard.log" 2>&1 < /dev/null &
echo "PRIVATE_PROBE_DIRECTORY=$directory"
/etc/init.d/failsafe-qmi stop
uci set network.wan.pdptype=ipv4v6
uci set network.wan.dhcpv6=0
uci set network.wan.delegate=0
uci commit network
logger -t failsafe-ipv6-probe 'Starting temporary dual-stack cellular capability test; LAN IPv6 remains disabled'
ifup wan
read -r started remainder < /proc/uptime
started=${started%%.*}
ipv4_address=false
ipv6_address=false
ipv6_route=false
ipv6_https=false
while :; do
    read -r elapsed remainder < /proc/uptime
    elapsed=${elapsed%%.*}
    [ "$((elapsed - started))" -lt 120 ] || break
    status=$(ubus call network.interface.wan status)
    if [ "$(jsonfilter -s "$status" -e '@.up')" = true ]; then
        if [ -n "$(jsonfilter -s "$status" -e '@["ipv4-address"][0].address')" ]; then ipv4_address=true; fi
        if jsonfilter -s "$status" -e '@["ipv6-address"][*].address' | grep -q '^[23]'; then ipv6_address=true; fi
        if ip -6 route show default dev wwan0 | grep -q '^default'; then ipv6_route=true; fi
        if [ "$ipv6_address" = true ] && [ "$ipv6_route" = true ]; then
            if wget -6 --no-proxy -q -T 10 -O "$directory/ipv6-trace" https://www.cloudflare.com/cdn-cgi/trace; then
                ipv6_https=true
                break
            fi
        fi
    fi
    sleep 5
done
printf '{"ipv4_address_observed":%s,"public_ipv6_observed":%s,"ipv6_default_route_observed":%s,"verified_ipv6_https":%s,"configuration_will_be_restored":true}\n' \
    "$ipv4_address" "$ipv6_address" "$ipv6_route" "$ipv6_https" | tee "$directory/result.json"
