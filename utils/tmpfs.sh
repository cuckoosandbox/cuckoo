#!/bin/sh
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <action> [paths...]"
    echo "action: create-backup, required-size, or create-symlinks."
    echo
    echo "create-backup <vmpath> <backuppath>"
    echo "required-size <path>"
    echo "initialize-mount <vmpath> <backuppath> <vmmount>"
    exit 1
fi

_create_backup() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Missing parameter(s) for create-backup.."
        exit 1
    fi

    local vmpath="$1", backuppath="$2"

    # Stop all running VMs.
    for vmname in $(VBoxManage list runningvms|cut -d'"' -f2); do
        VBoxManage controlvm "$vmname" poweroff
    done

    # Revert all VMs to the latest snapshot.
    for vmname in $(VBoxManage list vms|cut -d'"' -f2); do
        VBoxManage snapshot "$vmname" restorecurrent
    done

    # Copy all files to the backup directory.
    cp -rf "$vmpath/." "$backuppath"

    # Remove all logfiles, we're not interested in backing up those.
    rm -f $(find "$backuppath" -type f|grep "\.log")
}

_required_size() {
    if [ -z "$1" ]; then
        echo "Missing path parameter for required-size.."
        exit 1
    fi

    local path="$1"

    # Total size of all the files.
    local size="$(du -s "$path"|cut -f1)"

    # Round up by one gigabyte.
    echo "$(($size/1024/1024+1))G"
}

_initialize_mount() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
        echo "Missing parameter(s) for initialize-mount.."
        exit 1
    fi

    local vmpath="$1", backuppath="$2", vmmount="$3"

    # Copy all files from the backuppath to the vmmount.
    cp -r "$backuppath/." "$vmmount"

    # Make symlinks from the vmmount to the vmpath.
    cp -srf "$vmmount/." "$vmpath"
}

case "$1" in
    create-backup)
        if [ "$#" -ne 2 ]; then
            echo "create-backup <vmpath> <backuppath>"
            exit 1
        fi

        _create_backup "$2" "$3"
        ;;

    required-size)
        if [ "$#" -ne 1 ]; then
            echo "required-size <path>"
            exit 1
        fi

        _required_size "$2"
        ;;

    initialize-mount)
        if [ "$#" -ne 3 ]; then
            echo "initialize-mount <vmpath> <backuppath> <vmmount>"
            exit 1
        fi

        _initialize_mount "$2" "$3" "$4"
        ;;
esac
