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

MOUNT="/mnt/winxp/"

if [ ! -d "$MOUNT" ] || [ -z "$(ls -A "$MOUNT")" ]; then
    mkdir -p "$MOUNT"
    mount -o loop,ro "$2" "$MOUNT"
fi

VMS="/home/cuckoo/vms/"
VMSBACKUP="/home/cuckoo/vms-backup/"
VMDATA="/home/cuckoo/vm-data/"

mkdir -p "$VMDATA"

# Setup tmpfs to store the various Virtual Machines.
if [ ! -d "$VMS" ]; then
    mkdir -p "$VMS"

    if [ "$4" -ne 0 ]; then
        mount -o size=${4}G -t tmpfs tmpfs "$VMS"
    fi
fi

chown cuckoo:cuckoo "$VMS" "$VMDATA"

VMCLOAKCONF="$(mktemp)"

echo "[vmcloak]" > "$VMCLOAKCONF"
echo "cuckoo = $CUCKOO" >> "$VMCLOAKCONF"
echo "vm-dir = $VMS" >> "$VMCLOAKCONF"
echo "data-dir = $VMDATA" >> "$VMCLOAKCONF"
echo "iso-mount = $MOUNT" >> "$VMCLOAKCONF"
echo "serial-key = $3" >> "$VMCLOAKCONF"
echo "dependencies = dotnet40" >> "$VMCLOAKCONF"
echo "temp-dirpath = $VMTEMP" >> "$VMCLOAKCONF"
echo "tags = longterm" >> "$VMCLOAKCONF"

chown cuckoo:cuckoo "$VMCLOAKCONF"

# Unlock VMCloak just to be sure.
sudo -u cuckoo -i vmcloak --unlock

# Create a bunch of Virtual Machines.
for i in $(seq -w 1 "$1"); do
    sudo -u cuckoo -i \
        vmcloak -s "$VMCLOAKCONF" --hostonly-ip 192.168.56.1$i egg$i
done

rm -rf "$VMCLOAKCONF" "$VMTEMP"

# We create a backup of the Virtual Machines in case tmpfs is being used.
# Because if the machine for some reason does a reboot, all the contents of
# the tmpfs directory will be gone.
if [ "$4" -ne 0 ]; then
    sudo -u cuckoo -i cp -r "$VMS" "$VMSBACKUP"
fi
