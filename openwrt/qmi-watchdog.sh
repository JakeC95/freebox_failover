#!/bin/sh

check_connection() {
    status=$(ubus call network.interface.wan status 2>/dev/null) || return 20
    [ "$(jsonfilter -s "$status" -e '@.proto')" = qmi ] || return 20
    [ "$(jsonfilter -s "$status" -e '@.autostart')" = true ] || return 20
    [ "$(jsonfilter -s "$status" -e '@.pending')" = false ] || return 20
    [ "$(jsonfilter -s "$status" -e '@.up')" = true ] || return 21
    age=$(jsonfilter -s "$status" -e '@.uptime')
    [ "${age:-0}" -ge 30 ] || return 20
    [ "$(uci -q get network.wan.device)" = /dev/cdc-wdm0 ] || return 20
    client=$(jsonfilter -s "$status" -e '@.data.cid_4')
    case "$client" in
        ''|*[!0-9]*) return 20 ;;
    esac
    settings=$(uqmi -s -d /dev/cdc-wdm0 -t 5000 --set-client-id "wds,$client" --get-current-settings 2>/dev/null)
    case "$settings" in
        '"Out of call"'|'"Call failed"') return 11 ;;
    esac
    modem_ip=$(jsonfilter -s "$settings" -e '@.ipv4.ip' 2>/dev/null)
    modem_gateway=$(jsonfilter -s "$settings" -e '@.ipv4.gateway' 2>/dev/null)
    [ -n "$modem_ip" ] && [ -n "$modem_gateway" ] || return 12
    host_ip=$(jsonfilter -s "$status" -e '@["ipv4-address"][0].address')
    host_gateway=$(jsonfilter -s "$status" -e '@.route[0].nexthop')
    [ "$modem_ip" = "$host_ip" ] && [ "$modem_gateway" = "$host_gateway" ] || return 10
    return 0
}

if [ "${1:-}" = --check ]; then
    check_connection
    exit $?
fi

failures=0
last_restart=0
while sleep 15; do
    check_connection
    result=$?
    case "$result" in
        0|20) failures=0; continue ;;
        10|11|12|21) failures=$((failures + 1)) ;;
        *) failures=0; continue ;;
    esac
    read -r elapsed remainder < /proc/uptime
    elapsed=${elapsed%%.*}
    [ "$failures" -ge 3 ] && [ "$((elapsed - last_restart))" -ge 180 ] || continue
    logger -t failsafe-qmi "Refreshing WAN after repeated QMI state/address mismatch (reason $result)"
    ifup wan
    last_restart=$elapsed
    failures=0
done
