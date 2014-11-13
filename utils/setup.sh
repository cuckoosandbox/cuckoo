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

# Update apt repository and install required packages.
apt-get update -y
apt-get install -y sudo git python-dev python-pip postgresql libpq-dev \
    python-dpkt vim tcpdump libcap2-bin genisoimage

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

# Allow tcpdump to dump packet captures when executed as a normal user.
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Setup a Cuckoo user.
useradd cuckoo

CUCKOO="/home/cuckoo/cuckoo/"
VMTEMP="$(mktemp -d "/home/cuckoo/XXXXXX")"

# Fetch Cuckoo and VMCloak.
git clone git://github.com/cuckoobox/cuckoo.git "$CUCKOO"

mkdir -p "$VMTEMP"

chown -R cuckoo:cuckoo "/home/cuckoo/" "$CUCKOO" "$VMTEMP"
chmod 755 "/home/cuckoo/" "$CUCKOO" "$VMTEMP"

# Install required packages part two.
pip install psycopg2 vmcloak -r "$CUCKOO/requirements.txt"

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

if [ "$#" -eq 4 ]; then
    ./vmcloak-setup.sh "$@"
fi


echo "PostgreSQL connection string:  " \
    "postgresql://cuckoo:$PASSWORD@localhost/cuckoo"
