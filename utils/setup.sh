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
fi

# Update apt repository and install required packages.
apt-get update -y
apt-get install -y sudo git python-dev python-pip postgresql libpq-dev \
    python-dpkt vim tcpdump libcap2-bin genisoimage

# Install the most up-to-date version of VirtualBox available at the moment.
if [ ! -e "/usr/bin/VirtualBox" ]; then
    # Update our apt repository with "contrib."
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

# Allow tcpdump to dump packet captures when executed as a normal user.
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Setup a Cuckoo user.
useradd cuckoo

CUCKOO="/home/cuckoo/cuckoo/"
VMTEMP="/home/cuckoo/temp/"

# Fetch Cuckoo and VMCloak.
git clone git://github.com/cuckoobox/cuckoo.git "$CUCKOO"

mkdir -p "$VMTEMP"

chown -R cuckoo:cuckoo "/home/cuckoo/" "$CUCKOO" "$VMTEMP"
chmod 755 "/home/cuckoo/" "$CUCKOO" "$VMTEMP"

# Install required packages part two.
pip install sqlalchemy psycopg2 vmcloak -r "$CUCKOO/requirements.txt"

# Create a random password.
PASSWORD="$(tr -dc "[:alnum:]" < /dev/urandom|head -c ${1:-16})"

sql_query() {
    echo "$1"|sudo -u postgres psql
}

sql_query "DROP DATABASE cuckoo"
sql_query "CREATE DATABASE cuckoo"

sql_query "DROP USER cuckoo"
sql_query "CREATE USER cuckoo WITH PASSWORD '$PASSWORD'"

# Setup the VirtualBox hostonly network.
if [ -z "$(VBoxManage list hostonlyifs)" ]; then
    VBoxManage hostonlyif create
    VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
fi

# Run the magic iptables script that turns hostonly networks into full
# internet access.
vmcloak-iptables

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

echo "[vmcloak]" > /tmp/vmcloak.conf
echo "cuckoo = $CUCKOO" >> /tmp/vmcloak.conf
echo "vm-dir = $VMS" >> /tmp/vmcloak.conf
echo "data-dir = $VMDATA" >> /tmp/vmcloak.conf
echo "iso-mount = $MOUNT" >> /tmp/vmcloak.conf
echo "serial-key = $3" >> /tmp/vmcloak.conf
echo "dependencies = dotnet40" >> /tmp/vmcloak.conf
echo "temp-dirpath = $VMTEMP" >> /tmp/vmcloak.conf

chown cuckoo:cuckoo /tmp/vmcloak.conf

# Unlock VMCloak just to be sure.
sudo -u cuckoo -i vmcloak --unlock

# Create a bunch of Virtual Machines.
for i in $(seq -w 1 "$1"); do
    sudo -u cuckoo -i \
        vmcloak -s /tmp/vmcloak.conf --hostonly-ip 192.168.56.1$i egg$i
done

# We create a backup of the Virtual Machines in case tmpfs is being used.
# Because if the machine for some reason does a reboot, all the contents of
# the tmpfs directory will be gone.
if [ "$4" -ne 0 ]; then
    cp -r "$VMS" "$VMSBACKUP"
fi

echo "PostgreSQL connection string:  " \
    "postgresql://cuckoo:$PASSWORD@localhost/cuckoo"
