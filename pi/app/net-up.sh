#!/bin/sh
# One interface contract for firewall, routing and DHCP.
set -eu
exec /usr/bin/python3 /opt/geobox/lan.py --configure
