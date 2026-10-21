#!/bin/sh
set -eu

cat > /etc/config/dhcp <<'CONFIG'
config dnsmasq
    option domainneeded '1'
    option boguspriv '1'
    option rebind_protection '1'
    option localservice '1'
    option nonwildcard '1'
    option authoritative '0'
    option leasefile '/tmp/dhcp.leases'
    option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
    list interface 'lan'

config dhcp 'lan'
    option interface 'lan'
    option ignore '1'
    option ra 'disabled'
    option dhcpv6 'disabled'
    option ndp 'disabled'
CONFIG

mkdir -p /etc/dropbear
chmod 700 /etc/dropbear
printf '%s\n' '__SSH_PUBLIC_KEY__' > /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys

uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.1.253'
uci set network.lan.netmask='255.255.255.0'
uci -q delete network.lan.gateway || true
uci -q delete network.lan.dns || true
uci -q delete network.lan.ip6assign || true
uci -q delete network.globals.ula_prefix || true
uci -q delete network.wan || true
uci -q delete network.wan6 || true
uci set network.wan='interface'
uci set network.wan.proto='qmi'
uci set network.wan.device='/dev/cdc-wdm0'
uci set network.wan.apn='__CELLULAR_APN__'
uci set network.wan.auth='none'
uci set network.wan.pdptype='ip'
uci set network.wan.dhcp='0'
uci set network.wan.peerdns='1'
uci set network.wan.delegate='0'
uci set network.wan.auto='0'
uci set network.wan.metric='10'

uci set dropbear.@dropbear[0].Interface='lan'
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci set dropbear.@dropbear[0].GatewayPorts='off'

uci -q delete uhttpd.main.listen_http || true
uci -q delete uhttpd.main.listen_https || true
uci add_list uhttpd.main.listen_https='127.0.0.1:443'
uci set uhttpd.main.redirect_https='1'

uci set system.@system[0].hostname='failsafe4g-router'
uci set system.@system[0].timezone='UTC'
uci set system.@system[0].zonename='UTC'
uci set system.@system[0].log_size='128'
uci set system.ntp.enabled='1'
uci set system.ntp.enable_server='0'

for radio in $(uci -q show wireless | sed -n 's/^wireless\.\([^.=]*\)=wifi-device$/\1/p'); do
    uci set "wireless.$radio.disabled=1"
done

uci commit
/etc/init.d/uhttpd disable
if [ -x /etc/init.d/odhcpd ]; then
    /etc/init.d/odhcpd disable
fi
exit 0
