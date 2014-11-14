#!/bin/sh

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <vmcount> <winxp.iso> <serial-key> <tmpfs-size>"
    echo "vmcount: Amount of Virtual Machines to be created"
    echo "winxp.iso: Path to a Windows XP Installer ISO"
    echo "serial-key: Serial Key for the given Windows XP version"
    echo "tmpfs-size: Size, in gigabytes, to create a tmpfs for the "
    echo "    relevant VirtualBox files. It is advised to give it roughly"
    echo "    one gigabyte per VM and to have a few spare gigabytes "
    echo "    just in case."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "You'll probably want to run this script as root."
    exit 1
fi

./install.sh

if [ "$#" -eq 4 ]; then
    ./vmcloak-setup.sh "$@"
fi



