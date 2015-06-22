#!/bin/bash

echo "### NOTICE ###" >&2
echo "This script is a work-in-progress, has not been yet documented, " >&2
echo "and may not work as expected." >&2
echo "### END OF NOTICE ###" >&2

# Default values.
VMCOUNT="40"
ISOFILE=""
SERIALKEY=""
TMPFS="0"

usage() {
    echo "Usage: $0 [options...]"
    echo "-c --vmcount: Amount of Virtual Machines to be created."
    echo "-i --iso: Path to a Windows XP Installer ISO."
    echo "-s --serial-key: Serial Key for the given Windows XP version."
    echo "-t --tmpfs: Indicate tmpfs should be used for snapshots."
    exit 1
}

while [ "$#" -gt 0 ]; do
    option="$1"
    shift

    case "$option" in
        -h|--help)
            usage
            ;;

        -c|--vmcount)
            VMCOUNT="$1"
            shift
            ;;

        -i|--iso)
            ISOFILE="$1"
            shift
            ;;

        -s|--serial-key)
            SERIALKEY="$1"
            shift
            ;;

        -t|--tmpfs)
            TMPFS="1"
            ;;

        *)
            echo "$0: Invalid argument.. $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "You'll probably want to run this script as root."
    exit 1
fi

if [ -z "$ISOFILE" ]; then
    echo "Please specify the path to a Windows XP Installer ISO."
    exit 1
fi

if [ -z "$SERIALKEY" ]; then
    echo "Please specify a working serial key."
    exit 1
fi

# Update apt repository and install required packages.
apt-get update -y
apt-get install -y sudo git python-dev python-pip postgresql libpq-dev \
    python-dpkt vim tcpdump libcap2-bin genisoimage pwgen

# Install the most up-to-date version of VirtualBox available at the moment.
if [ ! -e "/usr/bin/VirtualBox" ]; then
    # Update our apt repository with "contrib".
    DEBVERSION="$(lsb_release -cs)"
    echo "deb http://download.virtualbox.org/virtualbox/debian " \
        "$DEBVERSION contrib" >> /etc/apt/sources.list.d/virtualbox.list

    # Add the VirtualBox public key to our apt repository.
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc \
        -O- | apt-key add -

    # Install the most recent VirtualBox.
    apt-get update -y
    apt-get install -y virtualbox-4.3
fi

# Allow tcpdump to dump packet captures when executed as a normal user.
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Setup a Cuckoo user.
useradd cuckoo -d "/home/cuckoo"

CUCKOO="/home/cuckoo/cuckoo"
VMTEMP="$(mktemp -d "/home/cuckoo/tempXXXXXX")"

# Fetch Cuckoo.
git clone git://github.com/cuckoobox/cuckoo.git "$CUCKOO"

chown -R cuckoo:cuckoo "/home/cuckoo/" "$CUCKOO" "$VMTEMP"
chmod 755 "/home/cuckoo/" "$CUCKOO" "$VMTEMP"

# Install required packages part two.
pip install --upgrade psycopg2 vmcloak -r "$CUCKOO/requirements.txt"

# Create a random password.
PASSWORD="$(pwgen -1 16)"

sql_query() {
    echo "$1"|sudo -u postgres psql
}

sql_query "DROP DATABASE cuckoo"
sql_query "CREATE DATABASE cuckoo"

sql_query "DROP USER cuckoo"
sql_query "CREATE USER cuckoo WITH PASSWORD '$PASSWORD'"

# Setup the VirtualBox hostonly network.
vmcloak-vboxnet0

# Run the magic iptables script that turns hostonly networks into full
# internet access.
vmcloak-iptables

MOUNT="/mnt/winxp/"

# The mount directory must exist and it must not be empty.
if [ ! -d "$MOUNT" ] || [ -z "$(ls -A "$MOUNT")" ]; then
    mkdir -p "$MOUNT"
    mount -o loop,ro "$ISOFILE" "$MOUNT"
fi

VMS="/home/cuckoo/vms/"
VMBACKUP="/home/cuckoo/vmbackup/"
VMMOUNT="/home/cuckoo/vmmount/"

mkdir -p "$VMS" "$VMBACKUP" "$VMMOUNT"
chown cuckoo:cuckoo "$VMS" "$VMBACKUP" "$VMMOUNT"

VMCLOAKCONF="$(mktemp)"

cat > "$VMCLOAKCONF" << EOF
[vmcloak]
cuckoo = $CUCKOO
vm-dir = $VMS
data-dir = $VMS
iso-mount = $MOUNT
serial-key = $SERIALKEY
temp-dirpath = $VMTEMP
EOF

chown cuckoo:cuckoo "$VMCLOAKCONF"

# Check whether the bird "bird0" already exists.
sudo -u cuckoo -i vmcloak-bird hddpath bird0
if [ "$?" -ne 0 ]; then
    echo "Creating the Virtual Machine bird.."
    vmcloak -u cuckoo -s "$VMCLOAKCONF" -r --bird bird0 --winxp
fi

# Kill all VirtualBox processes as otherwise the listening
# port for vmcloak-clone might still be in use..
vmcloak-killvbox

# Create various Virtual Machine eggs.
for i in $(seq 1 "$VMCOUNT"); do
    echo "Creating Virtual Machine egg$i.."
    vmcloak-clone -s "$VMCLOAKCONF" -u cuckoo --bird bird0 \
        --hostonly-ip "192.168.56.$((2+$i))" "egg$i"
done

rm -rf "$VMCLOAKCONF" "$VMTEMP"

if [ "$TMPFS" -ne 0 ]; then
    # Unmount just in case.
    umount "$VMMOUNT"

    # Copy all Virtual Machine data to the backup folder.
    sudo -u cuckoo -i "$CUCKOO/utils/tmpfs.sh" \
        create-backup "$VMS" "$VMBACKUP"

    # Calculate the required size for the tmpfs mount.
    REQSIZE="$("$CUCKOO/utils/tmpfs.sh" required-size "$VMBACKUP")"

    mount -o "size=$REQSIZE,uid=cuckoo,gid=cuckoo" -t tmpfs tmpfs "$VMMOUNT"

    # Copy all files to the mount and create all required symlinks.
    sudo -u cuckoo -i "$CUCKOO/utils/tmpfs.sh" \
        initialize-mount "$VMS" "$VMBACKUP" "$VMMOUNT"
fi

# Add "nmi_watchdog=0" to the GRUB commandline if it's not in there already.
if ! grep nmi_watchdog /etc/default/grub; then
    cat >> /etc/default/grub << EOF

# Add nmi_watchdog=0 to the GRUB commandline to prevent
# VirtualBox from kernel panicing when the load increases.
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT nmi_watchdog=0"
EOF
fi

# Recreate the GRUB configuration.
grub-mkconfig -o /boot/grub/grub.cfg

echo "PostgreSQL connection string:  " \
    "postgresql://cuckoo:$PASSWORD@localhost/cuckoo"
