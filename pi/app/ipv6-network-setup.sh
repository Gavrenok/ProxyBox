#!/bin/sh
# GeoBox IPv6 LAN infrastructure. The panel controls block/proxy in sing-box.
# Run only inside the installer's independent network rollback transaction.
# Back up the NM geobox-ap profile and /etc/dnsmasq.d/geobox-ipv6.conf first.
# This script never enables a direct WAN route or changes SSID/PSK/IPv4 settings.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

case "${1:---check}" in
    --check|--apply) mode=${1:---check} ;;
    *) echo 'Usage: ipv6-network-setup.sh --check|--apply' >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo 'root is required' >&2; exit 1; }
for cmd in nmcli dnsmasq nft ip sysctl python3; do
    command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }
done
nmcli connection show geobox-ap >/dev/null
[ "$(nmcli -g 802-11-wireless.mode connection show geobox-ap)" = ap ] || {
    echo 'geobox-ap is not an access point' >&2; exit 1;
}
# Refuse to advertise a network that the currently installed config cannot serve.
python3 - <<'PY'
import json
with open('/etc/geobox/sing-box.json') as f:
    config = json.load(f)
assert any(i.get('type') == 'tun' and i.get('interface_name') == 'sbtun'
           and 'fd77:6765:6f62:2::1/126' in i.get('address', [])
           for i in config.get('inbounds', [])), 'IPv6 TUN config is not installed'
PY
nft --check --file /opt/geobox/geobox.nft
dnsmasq --test
if [ "$mode" = --check ]; then
    echo 'IPv6 LAN preflight passed; no network settings changed'
    exit 0
fi

# Firewall and unreachable routes exist before IPv6 addresses or RA are enabled.
/opt/geobox/net-up.sh
nmcli connection modify geobox-ap \
    ipv6.method manual ipv6.addresses fd77:6765:6f62:1::1/64 \
    ipv6.gateway '' ipv6.routes '' ipv6.dns '' ipv6.dns-search '' \
    ipv6.never-default yes ipv6.ignore-auto-routes yes ipv6.ignore-auto-dns yes

install -d /etc/dnsmasq.d
conf=/etc/dnsmasq.d/geobox-ipv6.conf
tmp=$(mktemp /etc/dnsmasq.d/.geobox-ipv6.XXXXXX)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
cat > "$tmp" <<'EOF'
# GeoBox: fixed ULA LAN, SLAAC only. DNS is supplied via IPv4 DHCP at 10.77.0.1.
# Explicit empty option6 suppresses dnsmasq's default link-local RDNSS advertisement.
enable-ra
dhcp-range=fd77:6765:6f62:1::,ra-only,slaac,64,1h
dhcp-option=option6:dns-server
dhcp-option=option6:domain-search
ra-param=wlan0,30,90
EOF
dnsmasq --test --conf-file="$tmp"
chmod 644 "$tmp"
mv "$tmp" "$conf"
dnsmasq --test
# Reapply keeps the AP up when supported; otherwise NM briefly reconnects it.
if ! nmcli --wait 20 device reapply wlan0 >/dev/null 2>&1; then
    nmcli --wait 40 connection up geobox-ap >/dev/null
fi
sysctl -q -w net.ipv6.conf.wlan0.accept_ra=0
sysctl -q -w net.ipv6.conf.wlan0.autoconf=0
ip -6 address show dev wlan0 | grep -F 'fd77:6765:6f62:1::1/64' >/dev/null
systemctl restart dnsmasq
systemctl is-active --quiet dnsmasq
echo 'IPv6 LAN configured; DNS stays on IPv4; sing-box retains block/proxy policy'
