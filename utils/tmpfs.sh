#!/bin/sh
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <action> <vm-path> <data-path>"
    echo "action: create-backup, required-size, or create-symlinks."
    echo "vm-path: Path where all VM related files are stored."
    echo "data-path: Backup path where to store all files."
    exit 1
fi

_create_backup() {
    # Stop all running VMs.
    for vmname in $(VBoxManage list runningvms|cut -d'"' -f2); do
        VBoxManage controlvm "$vmname" poweroff
    done

    # Revert all VMs to the latest snapshot.
    for vmname in $(VBoxManage list vms|cut -d'"' -f2); do
        VBoxManage snapshot "$vmname" restorecurrent
    done

    # Copy all files to the backup directory.
    cp -rf "$VMPATH/." "$DATAPATH"

    # Remove all logfiles, we're not interested in backing up those.
    rm -f $(find "$DATAPATH" -type f|grep "\.log")
}

_required_size() {
    # Total size of all the files.
    local size="$(du -s "$DATAPATH"|cut -f1)"

    # Round up by one gigabyte.
    echo "$(($size/1024/1024+1))G"
}

_create_symlinks() {
    cp -sr "$DATAPATH/." "$VMPATH"
}

VMPATH="$2"
DATAPATH="$3"

case "$1" in
    create-backup)
        _create_backup
        ;;

    required-size)
        _required_size
        ;;

    create-symlinks)
        _create_symlinks
        ;;
esac
