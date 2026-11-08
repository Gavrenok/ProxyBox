#!/bin/sh
# GeoBox: маршрут для Wi-Fi клиентов. Всё, что пришло из wlan0, ищет дорогу в таблице 100,
# а там есть только sbtun (sing-box). Пока sing-box не запущен, там «недоступно» - утечки нет.
set -e
# Install the kill switch before enabling forwarding (including during boot).
nft -f /opt/geobox/geobox.nft
sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=2
sysctl -q -w net.ipv4.conf.default.rp_filter=2
while ip rule del iif wlan0 lookup 100 2>/dev/null; do :; done
ip rule add iif wlan0 lookup 100 priority 100
ip route replace unreachable default table 100 metric 9999
# IPv6 has its own policy table. Its unreachable route survives a vanished TUN.
ip -6 route replace unreachable default table 100 metric 9999
while ip -6 rule del iif wlan0 lookup 100 2>/dev/null; do :; done
ip -6 rule add iif wlan0 lookup 100 priority 100
sysctl -q -w net.ipv6.conf.all.forwarding=1
sysctl -q -w net.ipv6.conf.wlan0.accept_ra=0
sysctl -q -w net.ipv6.conf.wlan0.autoconf=0
