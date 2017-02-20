#!/usr/bin/env bash
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

# Abstract
# ---------
# A bootstrap script for an OS X host.
#
# Usage
# ---------
# Launch this script with -i flag to create a host-only network interface
# and assign it to the given VirtualBox guest machine:
# ./bootstrap_host.sh -i MyOSXVirtualMachine
#
# Or just launch it without any arguments to enable traffic forwarding
# for vboxnet0 host-only interface:
# ./bootstrap_host.sh

GUEST_IP="192.168.56.1"
INTERFACE="vboxnet0"

opt_create_interface=false; vmname="";
while getopts ":i:" opt; do
    case $opt in
        i) opt_create_interface=true; vmname="$OPTARG" ;;
        \?) echo "Invalid option -$OPTARG" >&2 ;;
    esac
done

# [1] Setup a host-only network interface (vboxnet0)
if [ "$opt_create_interface" == true ]; then
    if [[ ! -f $(which vboxmanage) ]]; then
        echo -e "[Error] Could not locate vboxmanage. Please, install Virtual Box first."
        exit 1
    fi
    # Let's also verify that a VM with this name actually exists
    # Note: `vboxmanage list vms` outputs data in the following format:
    #   "SandboxXP" {2b96015e-42e0-4662-b792-c738c2de155f}
    vm_exists=$(vboxmanage list vms | grep -c "\"$vmname\" {[0-9a-z\-]*}")
    if [ "$vm_exists" -ne 1 ]; then
        echo -e "[Error] Could not find a VM named \"$vmname\"."
        exit 1
    fi
    vboxmanage hostonlyif create
    # 192.168.56.1 is the default IP from `cuckoo.conf`
    vboxmanage hostonlyif ipconfig $INTERFACE --ip $GUEST_IP
    vboxmanage modifyvm "$vmname" --hostonlyadapter1 $INTERFACE
    vboxmanage modifyvm "$vmname" --nic1 hostonly
fi

# [2.1] Make sure vboxnet0 is up before doing anything with it
vboxmanage hostonlyif ipconfig $INTERFACE --ip $GUEST_IP
if [ "$(uname -s)" != "Darwin" ]; then
    echo "I can't setup traffic forwarding for your OS, sorry :("
else
    # [2.2] Enable traffic forwarding for vboxnet0 interface (for OS X only)
    sudo sysctl -w net.inet.ip.forwarding=1 &> /dev/null
    rules="nat on en1 from vboxnet0:network to any -> (en1)
    pass inet proto icmp all
    pass in on vboxnet0 proto udp from any to any port domain keep state
    pass quick on en1 proto udp from any to any port domain keep state"
    echo "$rules" > ./pfrules
    sudo pfctl -e -f ./pfrules
    rm -f ./pfrules
fi
