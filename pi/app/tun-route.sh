#!/bin/sh
# GeoBox: как только sing-box создал sbtun - направить туда трафик Wi-Fi клиентов
set -e
i=0
while [ "$i" -lt 40 ]; do
    if ip link show sbtun >/dev/null 2>&1; then
        ip link set sbtun up 2>/dev/null || true
        ip route replace default dev sbtun table 100 metric 1
        # Do not hide an IPv6 route failure: ExecStartPost must fail closed.
        ip -6 route replace unreachable default table 100 metric 9999
        ip -6 route replace default dev sbtun table 100 metric 1
        exit 0
    fi
    i=$((i + 1))
    sleep 0.5
done
echo 'sbtun так и не появился' >&2
exit 1
