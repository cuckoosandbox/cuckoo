#!/usr/bin/env bash
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

# This script consist of commands for seting a target VirtualBox VM network properties.
# In more details it creates a host-only network interface, assigns it to the VM and then
# enables traffic forwarding for this interface.
#
# Important notes:
# 	1. The target VirtualBox VM must actually exist.
# 	2. This script does handle only OS X at the moment.
#
# Usage: ./setup_vm_network.sh <VirtualBox VM name here>
#

# Colors are nice, aren't they?
RED='\033[0;31m'
GREEN='\033[0;32m'
CLEAR='\033[0m'
# A user-specified VM name
VM_NAME=$1

if [[ ! -f $(which vboxmanage) ]]; then
	echo -e "$RED[Error]$CLEAR Unable to find vboxmanage util. Please, install Virtual Box first."
	exit 1
fi

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 <your VM name here>"
	exit 0
fi

# Let's also verify that a VM with this name actually exists
# Note: `vboxmanage list vms` outputs data in the following format:
# 	"SandboxXP" {2b96015e-42e0-4662-b792-c738c2de155f}
vm_exists=`vboxmanage list vms | grep "\"$VM_NAME\" {[0-9a-z\-]*}" | wc -l`
if [ $vm_exists -ne 1 ]; then
	echo -e "$RED[Error]$CLEAR Unable to find a VM named \"$VM_NAME\". Did you spell it correctly?"
	exit 1
fi

echo "[*] Creating new host-only network interface…"
vboxmanage hostonlyif create
# with the default IP from `cuckoo.conf`
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
echo "[*] Assigning this interface to the VM…"
vboxmanage modifyvm "$VM_NAME" --hostonlyadapter1 vboxnet0
vboxmanage modifyvm "$VM_NAME" --nic1 hostonly
echo "[*] Enabling traffic forwarding… (that's system-wide, so I need the administrator's password)"
sudo sysctl -w net.inet.ip.forwarding=1 &> /dev/null
# Apply the folowing rules for forwarding traffic
# from and to the host-only interface
rules="nat on en1 from vboxnet0:network to any -> (en1)
pass inet proto icmp all
pass in on vboxnet0 proto udp from any to any port domain keep state
pass quick on en1 proto udp from any to any port domain keep state"
echo "$rules" > ./pfrules
sudo pfctl -e -f ./pfrules
rm -f ./pfrules

echo -e "[*] ${GREEN}Done!${CLEAR}\nNow launch your guest OS and use the following network properties:"
echo -e "       Static IP:\t192.168.56.101"
echo -e "            Mask:\t255.255.255.0"
echo -e "Gateway (router):\t192.168.56.1"
echo -e "You may also want to use Google DNS as your DNS server:"
echo -e "             DNS:\t8.8.8.8 (and/or 8.8.4.4)"
