#!/usr/bin/env bash
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

# Abstract
# ---------
# This is a bootstrap script for an OS X guest machine. It's able to:
#   0) Update network settings (Ethernet)
#   1) Install the anti-antitracing kernel module (aka `pt_deny_attach` kext)
#   2) Patch /etc/sudoers to allow the user to launch `dtrace` and `date`
#      without a password
#   3) Load and launch the Cuckoo guest agent (agent.py)
#
# Usage
# ---------
# The first two steps are optional, so by default this script will only download
# and execute the arent.py. To install the kernel module or to patch the sudoers
# file, use -k and -s flags respectively:
#
# ./bootstrap_guest.sh -k      -- for loading the kext
# ./bootstrap_guest.sh -s      -- for patching /etc/sudoers
# ./bootstrap_guest.sh -k -s   -- for both actions
#

# Network settings
IP_ADDRESS="192.168.56.101"
SUBNET_MASK="255.255.255.0"
ROUTER_ADDRESS="192.168.56.1"
DNS_SERVERS=("208.67.220.220" "208.67.222.222")
# Cuckoo agent locations
AGENT_DIR="/Users/Shared"
AGENT_URL="https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/agent/agent.py"

opt_patch_sudoers=false; opt_install_kext=false;
while getopts ":sk" opt; do
  case $opt in
    s) opt_patch_sudoers=true ;;
    k) opt_install_kext=true ;;
    \?) echo "Invalid option -$OPTARG" >&2 ;;
  esac
done

# [0] Setup network
sudo networksetup -setmanual Ethernet $IP_ADDRESS $SUBNET_MASK $ROUTER_ADDRESS
sudo networksetup -setdnsservers Ethernet "${DNS_SERVERS[@]}"

# [1] Install `pt_deny_attach` kext.
if [ "$opt_install_kext" == true ]; then
    # echo "[INFO]: Downloading 'pt_deny_attach' kext"
    # echo "[INFO]: Loading the kext into the kernel"
    # TODO(rodionovd): download and load the kext
    echo "[WARNING]: pt_deny_attach kext loading is not implemented yet."
fi

# [2] Patch /etc/sudoers to enable passwordless sudo for `dtrace` and `date`
if [ "$opt_patch_sudoers" == true ]; then
    echo "[INFO]: Patching /etc/sudoers to enable passwordless dtrace for current user"
    user=$(whoami)
    if [ -z "$user" ]; then
        echo "[ERROR]: $(whoami) failed. /etc/sudoers wasn't patched."
    else
        # Since `>>` redirect is done by the shell itself and it drops all privileges,
        # we must run this command in a subshell.
        sudo sh -c "echo \"$user\tALL=(root) NOPASSWD: /usr/sbin/dtrace\" >> /etc/sudoers"
        sudo sh -c "echo \"$user\tALL=(root) NOPASSWD: /bin/date\" >> /etc/sudoers"
    fi
fi

# [3] Download agent.py into /Users/Shared
echo "[INFO]: Downloading the Cuckoo guest agent"
curl -o "$AGENT_DIR"/agent.py "$AGENT_URL"
# [3.1] Install dependencies
sudo easy_install pip
(cd "$(dirname "$0")/.." && sudo -H pip install -r requirements.txt)
# [4] and run it
echo "[INFO]: Launching the Cuckoo guest agent"
python "$AGENT_DIR"/agent.py
