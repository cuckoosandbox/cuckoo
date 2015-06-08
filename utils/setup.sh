#!/bin/bash

echo "### NOTICE ###" >&2
echo "This script is a work-in-progress, has not been yet documented, " >&2
echo "and may not work as expected." >&2
echo "### END OF NOTICE ###" >&2

# Default values.
WIN7="0"
VMCOUNT="40"
ISOFILE=""
SERIALKEY=""
TMPFS="0"
TAGS=""
INTERFACES="eth0 wlan0"
CLEAN="0"
DEPENDENCIES=""

usage() {
    echo "Usage: $0 [options...]"
    echo "-7 --win7:         Create Windows 7 x64 Virtual Machines."
    echo "   --win7x86:      Create Windows 7 x86 Virtual Machines."
    echo "-c --vmcount:      Amount of Virtual Machines to be created."
    echo "-i --iso:          Path to a Windows XP Installer ISO."
    echo "-s --serial-key:   Serial Key for the given Windows XP version."
    echo "-t --tmpfs:        Indicate tmpfs should be used for snapshots."
    echo "-T --tags:         Tags for the Virtual Machines."
    echo "-I --interfaces:   Interfaces to route Virtual Machine internet"
    echo "                   through. Defaults to eth0 wlan0."
    echo "-C --clean:        Clean the Cuckoo setup."
    echo "-d --dependencies: Dependencies to install in the Virtual Machine."
    exit 1
}

MOUNTOS="winxp"
WINOS="--winxp"

while [ "$#" -gt 0 ]; do
    option="$1"
    shift

    case "$option" in
        -h|--help)
            usage
            ;;

        -7|--win7)
            WIN7="1"
            MOUNTOS="win7"
            WINOS="--win7x64"
            ;;

        --win7x86)
            WIN7="1"
            MOUNTOS="win7"
            WINOS="--win7"
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

        -T|--tags)
            TAGS="$1"
            shift
            ;;

        -I|--interfaces)
            INTERFACES="$1"
            shift
            ;;

        -C|--clean)
            CLEAN="1"
            ;;

        -d|--dependencies)
            DEPENDENCIES="$1"
            shift
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

if [ "$CLEAN" -ne 0 ]; then
    yes|sudo -u cuckoo -i vmcloak-removevms
    umount /home/cuckoo/vmmount
    rm -rf /home/cuckoo/{.config,.vmcloak,vmbackup,vmmount,vms}
    exit 0
fi

if [ -z "$ISOFILE" ]; then
    echo "Please specify the path to a Windows XP Installer ISO."
    exit 1
fi

if [ "$WIN7" -eq 0 ] && [ -z "$SERIALKEY" ]; then
    echo "Please specify a working serial key."
    exit 1
fi

# Update apt repository and install required packages.
apt-get update -y --force-yes
apt-get install -y --force-yes sudo git python-dev python-pip postgresql \
    libpq-dev python-dpkt vim tcpdump libcap2-bin genisoimage pwgen \
    htop tig mosh

# Create the main postgresql cluster. In recent versions of Ubuntu Server
# 14.04 you have to do this manually. If it already exists this command
# will simply fail.
pg_createcluster 9.3 main --start

# Install the most up-to-date version of VirtualBox available at the moment.
if [ ! -e "/usr/bin/VirtualBox" ]; then
    # Update our apt repository with "contrib".
    DEBVERSION="$(lsb_release -cs)"
    echo "deb http://download.virtualbox.org/virtualbox/debian " \
        "$DEBVERSION contrib" >> /etc/apt/sources.list

    # Add the VirtualBox public key to our apt repository.
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc \
        -O- | apt-key add -

    # Install the most recent VirtualBox.
    apt-get update -y
    apt-get install -y virtualbox-4.3
fi

# Install the VirtualBox Extension Pack for VRDE support.
if grep "Extension Packs: 0" <(VBoxManage list extpacks); then
    VBOXVERSION="$(VBoxManage --version|sed s/r/\-/)"
    PRETTYNAME="Oracle_VM_VirtualBox_Extension_Pack-$VBOXVERSION"
    wget "http://cuckoo.sh/vmcloak-files/${PRETTYNAME}.vbox-extpack"
    VBoxManage extpack install --replace "${PRETTYNAME}.vbox-extpack"
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
vmcloak-iptables 192.168.56.1/24 "$INTERFACES"

MOUNT="/mnt/$MOUNTOS/"

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
vm-dir = $VMBACKUP
data-dir = $VMBACKUP
iso-mount = $MOUNT
serial-key = $SERIALKEY
temp-dirpath = $VMTEMP
tags = $TAGS
EOF

if [ -n "$DEPENDENCIES" ]; then
    echo "dependencies = $DEPENDENCIES" >> "$VMCLOAKCONF"
fi

chown cuckoo:cuckoo "$VMCLOAKCONF"

# Delete the cuckoo1 machine that is included in the VirtualBox configuration
# by default.
"$CUCKOO/utils/machine.py" --delete cuckoo1

# Check whether the bird "bird0" already exists.
sudo -u cuckoo -i vmcloak-bird hddpath bird0
if [ "$?" -ne 0 ]; then
    echo "Creating the Virtual Machine bird.."
    vmcloak -u cuckoo -s "$VMCLOAKCONF" -r --bird bird0 "$WINOS" --vrde
fi

# Kill all VirtualBox processes as otherwise the listening
# port for vmcloak-clone might still be in use..
vmcloak-killvbox

# Create various Virtual Machine eggs.
for i in $(seq 1 "$VMCOUNT"); do
    # Ensure this Virtual Machine has not already been created.
    if grep '"'egg$i'"' <(sudo -u cuckoo -i VBoxManage list vms); then
        continue
    fi

    echo "Creating Virtual Machine egg$i.."
    vmcloak-clone -s "$VMCLOAKCONF" -u cuckoo --bird bird0 \
        --hostonly-ip "192.168.56.$((2+$i))" "egg$i"
done

rm -rf "$VMCLOAKCONF" "$VMTEMP"

# Remove all Virtual Machine related logfiles, we're not interested
# in keeping those.
rm -f $(find "$VMBACKUP" -type f|grep "\.log")

_symlink_directory() {
    # Create directories in the target directory for each directory found in
    # the source directory. Then create a symlink for every file found.
    if [ ! -d "$1" ] || [ ! -d "$2" ]; then
        echo "Missing parameter(s) for symlink-directory.."
        exit 1
    fi

    local source="$1" target="$2"

    # Create each directory.
    for dirname in $(cd "$source" && find * -type d); do
        sudo -u cuckoo mkdir -p "$target/$dirname"
    done

    # Make symlinks of all files.
    for filename in $(cd "$source" && find * -type f); do
        sudo -u cuckoo ln -fs "$source/$filename" "$target/$filename"
    done
}

if [ "$TMPFS" -ne 0 ]; then
    # Unmount just in case it was mounted.
    umount "$VMMOUNT"

    # Calculate the required size for the tmpfs mount. Round up to megabytes.
    REQSIZE="$(du -s "$VMBACKUP"|cut -f1)"
    REQSIZE="$(($REQSIZE/1024+1))M"

    mount -o "size=$REQSIZE,uid=cuckoo,gid=cuckoo" -t tmpfs tmpfs "$VMMOUNT"

    # Copy all files from the backup to the mount.
    sudo -u cuckoo cp -rf "$VMBACKUP/." "$VMMOUNT"

    # Create symlinks from the mount into the vms directory.
    _symlink_directory "$VMMOUNT" "$VMS"
else
    # Create symlinks from the backup into the vms directory.
    _symlink_directory "$VMBACKUP" "$VMS"
fi

# Install the Upstart/SystemV scripts.
"$CUCKOO/utils/service.sh" install

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
