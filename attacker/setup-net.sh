#!/usr/bin/env bash
# Run inside Kali: static 10.66.0.50 on the honeynet NIC, no gateway (lab stays offline).
set -euo pipefail
IFACE="${1:-eth1}"
IP="${2:-10.66.0.50/24}"

nmcli -t -f NAME con show | grep -qx honeynet && nmcli con delete honeynet
nmcli con add type ethernet ifname "$IFACE" con-name honeynet \
    ipv4.method manual ipv4.addresses "$IP" ipv4.never-default yes \
    ipv6.method disabled autoconnect yes
nmcli con up honeynet
ip -br addr show "$IFACE"
