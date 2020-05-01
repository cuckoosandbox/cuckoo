#!/bin/sh
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

tap_iface_name=$1
bridge_iface_ip=10.3.2.1
bridge_iface_name=cuckoo_avd_br
default_iface_name=$(sudo route | grep -m1 "^default" | grep -o "[^ ]*$")

fwd_br_default_rule="FORWARD -i $bridge_iface_name -o $default_iface_name -j ACCEPT"
fwd_default_br_rule="FORWARD -i $default_iface_name -o $bridge_iface_name -m state --state RELATED,ESTABLISHED -j ACCEPT"
route_nat_rule="POSTROUTING -o $default_iface_name -j MASQUERADE"

bridge_exists=0
for iface in $(ls /sys/class/net); do
    if [ $iface = $bridge_iface_name ]; then
        bridge_exists=1
        break
    fi
done
if [ $bridge_exists -eq 0 ]; then
    sudo ip link add $bridge_iface_name type bridge
    sudo ip addr add $bridge_iface_ip/24 dev $bridge_iface_name
    sudo ip link set $bridge_iface_name up
fi

sudo sysctl -w net.ipv4.conf.$bridge_iface_name.forwarding=1 >/dev/null
sudo sysctl -w net.ipv4.conf.$default_iface_name.forwarding=1 >/dev/null

active_iptables_rules=$(sudo iptables-save)
case "$active_iptables_rules" in
    *"$fwd_br_default_rule"*)
        ;;
    *)
        sudo iptables -A $fwd_br_default_rule
        ;;
esac
case "$active_iptables_rules" in
    *"$fwd_default_br_rule"*)
        ;;
    *)
        sudo iptables -A $fwd_default_br_rule
        ;;
esac
case "$active_iptables_rules" in
    *"$route_nat_rule"*)
        ;;
    *)
        sudo iptables -t nat -A $route_nat_rule
        ;;
esac

sudo ip link set $tap_iface_name master $bridge_iface_name
sudo ip link set $tap_iface_name up
