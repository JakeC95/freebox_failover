#!/bin/sh
set -eu

[ "$(awk -F: '$1 == "root" && $2 != "" && $2 != "!" && $2 != "*" { print 1 }' /etc/shadow)" = 1 ]
[ "$(uci get network.lan.ipaddr)" = '192.168.1.253' ]
[ -c /dev/cdc-wdm0 ]

cat > /etc/sysctl.d/90-failsafe-router.conf <<'CONFIG'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
CONFIG
sysctl -p /etc/sysctl.d/90-failsafe-router.conf

uci set dropbear.@dropbear[0].LocalPortForward='off'
uci set dropbear.@dropbear[0].RemotePortForward='off'
uci set dropbear.@dropbear[0].IdleTimeout='600'
uci set dropbear.@dropbear[0].MaxAuthTries='3'
uci -q delete uhttpd.main.listen_https || true
uci add_list uhttpd.main.listen_https='192.168.1.253:443'
uci set uhttpd.main.max_connections='20'
uci set uhttpd.main.max_requests='2'
uci set uhttpd.defaults.commonname='failsafe4g-router'
uci set uhttpd.defaults.key_type='ec'
uci set uhttpd.defaults.ec_curve='P-256'
uci set system.@system[0].description='Ethernet LTE backup; DHCP and IPv6 disabled'
for section in $(uci show firewall | sed -n 's/^firewall\.\([^=]*\)=rule$/\1/p'); do
    rule_name=$(uci -q get "firewall.$section.name")
    case "$rule_name" in
        Allow-IPSec-ESP|Allow-ISAKMP) uci set "firewall.$section.enabled=0" ;;
    esac
done
uci commit
/etc/init.d/firewall reload

umask 077
if [ ! -s /etc/uhttpd.crt ] || [ ! -s /etc/uhttpd.key ]; then
    px5g selfsigned -der -days 397 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout /etc/uhttpd.key -out /etc/uhttpd.crt \
        -subj /CN=failsafe4g-router \
        -addext extendedKeyUsage=serverAuth \
        -addext subjectAltName=DNS:failsafe4g-router
fi
/etc/init.d/dropbear restart
/etc/init.d/uhttpd enable
/etc/init.d/uhttpd restart

uqmi -d /dev/cdc-wdm0 -t 10000 --set-device-operating-mode online
uqmi -d /dev/cdc-wdm0 -t 10000 --set-network-roaming any
uci set network.wan.auto='1'
uci set network.wan.timeout='60'
uci set network.wan.delay='10'
uci set network.wan.dhcp='0'
uci set network.wan.pdptype='ip'
uci set network.wan.autoconnect='1'
uci commit network
ifup wan
if [ -x /usr/libexec/failsafe-qmi-watchdog ] && [ -x /etc/init.d/failsafe-qmi ]; then
    for backup_path in /usr/libexec/failsafe-qmi-watchdog /etc/init.d/failsafe-qmi /etc/sysctl.d/90-failsafe-router.conf /etc/rc.d/S95failsafe-qmi /etc/rc.d/K15failsafe-qmi; do
        grep -qxF "$backup_path" /etc/sysupgrade.conf || printf '%s\n' "$backup_path" >> /etc/sysupgrade.conf
    done
    /etc/init.d/failsafe-qmi enable
    /etc/init.d/failsafe-qmi start
fi
sync
