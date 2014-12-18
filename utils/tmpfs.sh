#!/bin/sh
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <action> <vm-path> <data-path>"
    echo "action: create-backup, required-size, or create-symlinks."
    echo "vm-path: Path where all VM related files are stored."
    echo "data-path: Backup path where to store all files."
    exit 1
fi

_create_backup() {
    if [ -z "$VMPATH" ] || [ -z "$DATAPATH" ]; then
        echo "Missing parameter(s) for create-backup.."
        exit 1
    fi

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
    if [ -z "$1" ]; then
        echo "Missing path parameter for required-size.."
        exit 1
    fi

    # Total size of all the files.
    local size="$(du -s "$1"|cut -f1)"

    # Round up by one gigabyte.
    echo "$(($size/1024/1024+1))G"
}

_create_symlinks() {
    if [ -z "$VMPATH" ] || [ -z "$DATAPATH" ]; then
        echo "Missing parameter(s) for create-symlinks.."
        exit 1
    fi

    cp -sr "$DATAPATH/." "$VMPATH"
}

VMPATH="$2"
DATAPATH="$3"

case "$1" in
    create-backup)
        _create_backup
        ;;

    required-size)
        _required_size "$2"
        ;;

    create-symlinks)
        _create_symlinks
        ;;
esac
