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
BASEDIR="/home/cuckoo"
VMCHECKUP="0"
LONGTERM="0"
CPUCOUNT="1"

usage() {
    echo "Usage: $0 [options...]"
    echo "-S --settings:     Load configuration from a file."
    echo "-7 --win7:         Create Windows 7 x64 Virtual Machines."
    echo "   --win7x86:      Create Windows 7 x86 Virtual Machines."
    echo "-c --vmcount:      Amount of Virtual Machines to be created."
    echo "-i --iso:          Path to the Windows Installer ISO."
    echo "-s --serial-key:   Serial Key for the given Windows XP version."
    echo "-t --tmpfs:        Indicate tmpfs should be used for snapshots."
    echo "-T --tags:         Tags for the Virtual Machines."
    echo "-I --interfaces:   Interfaces to route Virtual Machine internet"
    echo "                   through. Defaults to eth0 wlan0."
    echo "-C --clean:        Clean the Cuckoo setup."
    echo "-d --dependencies: Dependencies to install in the Virtual Machine."
    echo "-b --basedir:      Base directory for Virtual Machine files."
    echo "-V --vms:          Only check Virtual Machines, don't re-setup."
    echo "-l --longterm:     Indicate this is a longterm analysis setup."
    echo "-u --cpucount:     Amount of CPUs per Virtual Machine."
    exit 1
}

EGGNAME="winxp"
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
            EGGNAME="win7x64"
            MOUNTOS="win7"
            WINOS="--win7x64"
            ;;

        --win7x86)
            WIN7="1"
            EGNNAME="win7x86"
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

        -b|--basedir)
            BASEDIR="$1"
            shift
            ;;

        -S|--settings)
            SETTINGS="$1"
            shift
            ;;

        -V|--vms)
            VMCHECKUP="1"
            ;;

        -l|--longterm)
            LONGTERM="1"
            ;;

        -u|--cpucount)
            CPUCOUNT="$1"
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
    rm -rf /home/cuckoo/{.config,.vmcloak,vmmount}
    rm -rf /home/cuckoo/{cuckoo,cuckoo.git}
    rm -rf "$BASEDIR/vms" "$BASEDIR/vmbackup"
    rm -rf /opt/cuckoo
    exit 0
fi

# Load configuration settings from a file if one has been provided.
# Note that any values in the configuration file will overwrite
# settings provided on the command-line.
if [ -n "$SETTINGS" ]; then
    . "$SETTINGS"
fi

if [ -z "$ISOFILE" ]; then
    echo "Please specify the path to a Windows XP or Windows 7 Installer ISO."
    exit 1
fi

if [ "$WIN7" -eq 0 ] && [ -z "$SERIALKEY" ]; then
    echo "Please specify a working serial key."
    exit 1
fi

if [ "$TMPFS" -ne 0 ] && [ "$LONGTERM" -ne 0 ]; then
    echo "It is not recommended to use tmpfs in a longterm setup."
    echo "Please update your settings or remove this check."
    exit 1
fi

if [ "$LONGTERM" -ne 0 ] && [ "$VMCOUNT" -ne 0 ]; then
    echo "In longterm mode virtual machines should not be created through the"
    echo "setup.sh script - this is handled by the vm cronjob."
    exit 1
fi

_clone_cuckoo() {
    local gitrepo=""

    # Fetch Cuckoo or in the case of a longterm setup, longcuckoo.
    if [ "$LONGTERM" -eq 0 ]; then
        sudo -u cuckoo -i \
            git clone --bare https://github.com/cuckoosandbox/cuckoo.git

        gitrepo="cuckoo.git"
    else
        sudo -u cuckoo -i \
            git clone --bare https://github.com/jbremer/longcuckoo.git

        gitrepo="longcuckoo.git"
    fi

    sudo -u cuckoo -i tee "$gitrepo/hooks/post-receive" << EOF
#!/bin/bash

read commit

if ! echo \$commit|grep production$; then
    echo -e "\\e[31mWe only check out changes to the production branch.\\e[0m"
    exit
fi

GIT_WORK_TREE=/opt/cuckoo git checkout -f production
EOF

    mkdir -p "/opt/cuckoo"
    chown cuckoo:cuckoo "/opt/cuckoo"
    chmod 755 "/home/cuckoo/" "/opt/cuckoo"
    sudo -u cuckoo -i chmod +x "$gitrepo/hooks/post-receive"

    # Checkout master branch of the repository (if this was not done already).
    if [ -z "$(ls -A /opt/cuckoo)" ]; then
        sudo -u cuckoo -i \
            git --work-tree /opt/cuckoo --git-dir "$gitrepo" checkout -f master
    fi

    # Add the Suricata reboot crontab entry.
    if ! grep suricata.sh <(crontab -l); then
        (crontab -l ; echo @reboot /opt/cuckoo/utils/suricata.sh)|crontab -
    fi

    # Delete the cuckoo1 machine that is included in the VirtualBox
    # configuration by default.
    sudo -u cuckoo -i "/opt/cuckoo/utils/machine.py" --delete cuckoo1
}

_setup() {
    # All functionality related to setting up the machine - this is not
    # required when doing a Virtual Machine checkup.

    # Add the VirtualBox apt repository.
    if [ ! -e /etc/apt/sources.list.d/virtualbox.list ]; then
        # Update our apt repository with VirtualBox "contrib".
        DEBVERSION="$(lsb_release -cs)"
        echo "deb http://download.virtualbox.org/virtualbox/debian" \
            "$DEBVERSION contrib" >> /etc/apt/sources.list.d/virtualbox.list

        # Add the VirtualBox public key to our apt repository.
        wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- \
            | apt-key add -
    fi

    # Add the ElasticSearch apt repository.
    if [ ! -e /etc/apt/sources.list.d/elasticsearch.list ]; then
        echo "deb http://packages.elastic.co/elasticsearch/2.x/debian" \
            "stable main" >> /etc/apt/sources.list.d/elasticsearch.list

        wget -q https://packages.elastic.co/GPG-KEY-elasticsearch -O- \
            | sudo apt-key add -
    fi

    # Update apt repository and install required packages.
    apt-get update -y --force-yes
    apt-get install -y --force-yes sudo git python-dev python-pip postgresql \
        libpq-dev python-dpkt vim tcpdump libcap2-bin genisoimage pwgen \
        htop tig mosh mongodb uwsgi uwsgi-plugin-python nginx virtualbox-4.3 \
        libffi-dev libxml2-dev libxslt1-dev libjpeg-dev samba-common-bin \
        ethtool elasticsearch linux-headers-$(uname -r)

    # Create the main postgresql cluster. In recent versions of Ubuntu Server
    # 14.04 you have to do this manually. If it already exists this command
    # will simply fail.
    pg_createcluster 9.3 main --start

    # Install the VirtualBox Extension Pack for VRDE support.
    VBOXVERSION="$(VBoxManage --version|sed s/r/\-/)"
    PRETTYNAME="Oracle_VM_VirtualBox_Extension_Pack-$VBOXVERSION"
    wget "http://cuckoo.sh/vmcloak-files/${PRETTYNAME}.vbox-extpack"
    VBoxManage extpack install --replace "${PRETTYNAME}.vbox-extpack"
    rm -f "${PRETTYNAME}.vbox-extpack"

    # Allow tcpdump to dump packet captures when executed as a normal user.
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

    # Setup a Cuckoo user.
    useradd cuckoo -d /home/cuckoo -s /bin/bash
    mkdir -p /home/cuckoo
    chown cuckoo:cuckoo /home/cuckoo

    # Copy any authorized keys from the current user to the cuckoo user.
    mkdir -p /home/cuckoo/.ssh
    cp ~/.ssh/authorized_keys /home/cuckoo/.ssh/authorized_keys
    chown cuckoo:cuckoo /home/cuckoo/.ssh/authorized_keys

    # Add the www-data user to the cuckoo group.
    adduser www-data cuckoo

    # TODO Somehow vmtemp is not properly propagated into the vmcloak
    # configuration thing, having to run the setup.sh script twice to
    # actually start creating the bird.
    VMTEMP="$(mktemp -d "/home/cuckoo/tempXXXXXX")"

    chown cuckoo:cuckoo "/home/cuckoo/"
    chown -R cuckoo:cuckoo "$VMTEMP"
    chmod 755 "/home/cuckoo/" "$VMTEMP"

    # Install required packages part two.
    pip install --upgrade mitmproxy psycopg2 vmcloak

    # Clone the Cuckoo repository and initialize it.
    _clone_cuckoo

    # Install required packages part three.
    pip install -r "/opt/cuckoo/requirements.txt"

    # Create a random password.
    # PASSWORD="$(pwgen -1 16)"
    PASSWORD="cuckoo"

    sql_query() {
        echo "$1"|sudo -u postgres psql
    }

    sql_query "DROP DATABASE cuckoo"
    sql_query "CREATE DATABASE cuckoo"

    sql_query "DROP USER cuckoo"
    sql_query "CREATE USER cuckoo WITH PASSWORD '$PASSWORD'"

    # Install the Upstart/SystemV scripts.
    /opt/cuckoo/utils/service.sh -c /opt/cuckoo install

    # Fetch the community signatures and monitoring binaries.
    sudo -u cuckoo -i /opt/cuckoo/utils/community.py -wafb master

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

    # Increase the file descriptor limits. TODO How to set it for just the cuckoo
    # user? Doesn't seem to work when using 'cuckoo' instead of '*'.
    if ! grep "* soft nofile" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << EOF

# Set the file descriptor limit fairly high.
* soft nofile 499999
* hard nofile 999999
EOF
    fi

    # For longterm setups we install the VM provisioning script and cronjob.
    if [ "$LONGTERM" -ne 0 ]; then
        CRONJOB="/home/cuckoo/vmprovision.sh"

        # Install the machine cronjob.
        "/opt/cuckoo/utils/experiment.py" machine-cronjob install \
            "cpucount=$CPUCOUNT" "path=$CRONJOB" "basedir=$BASEDIR"
        chown cuckoo:cuckoo "$CRONJOB"
        chmod +x "$CRONJOB"

        # We want to run the vm provisioning cronjob every five minutes.
        # Ensure that we only install the cronjob entry once.
        CRONTAB="$(crontab -u cuckoo -l)"
        if [[ ! "$CRONTAB" =~ "vmprovision.sh" ]]; then
            (echo "$CRONTAB" ; echo "*/5 * * * * $CRONJOB")|crontab -u cuckoo -
        fi
    fi

    # TODO Should be automated away.
    echo "PostgreSQL connection string:  " \
        "postgresql://cuckoo:$PASSWORD@localhost/cuckoo"
}

_create_virtual_machines() {
    # Prepare the machine for virtual machines and actually create them.

    # Ensure that vboxnet0 is up and running.
    vmcloak-vboxnet0

    # Kill all VirtualBox processes as otherwise the listening port for
    # vmcloak-clone might still be in use.. TODO This can probably be removed.
    vmcloak-killvbox

    if [ -z "$SERIALKEY" ]; then
        serial=""
    else
        serial="--serial-key $SERIALKEY"
    fi

    options="$serial --cpus $CPUCOUNT"

    # Attempt to create a new image if one does not already exist.
    sudo -u cuckoo -i vmcloak init "${EGGNAME}_bird" "$WINOS" $options
    if [ "$?" -eq 0 ]; then
        sudo -u cuckoo -i vmcloak install "${EGGNAME}_bird" $DEPENDENCIES
    fi

    # Create various Virtual Machine eggs.
    for i in $(seq 1 "$VMCOUNT"); do
        name="${EGGNAME}_egg$i"

        # Ensure this Virtual Machine has not already been created.
        if grep '"'$name'"' <(sudo -u cuckoo -i VBoxManage list vms); then
            continue
        fi

        # As vmcloak-clone will add an entry for this node we remove it just
        # in case it did already exist.
        "/opt/cuckoo/utils/machine.py" --delete "$name"

        # Delete any remaining files for this Virtual Machine just in case
        # they were still present.
        rm -rf "$VMBACKUP/$name"

        echo "Creating Virtual Machine $name.."
        sudo -u cuckoo -i vmcloak snapshot "${EGGNAME}_bird" \
            "$name" "192.168.56.$((2+$i))"

        echo "Registering Virtual Machine $name.."
        sudo -u cuckoo -i vmcloak register "$name" /opt/cuckoo
    done

    rm -rf "$VMCLOAKCONF" "$VMTEMP"

    # In longterm modes we have a different script that provides VMs for us.
    if [ "$LONGTERM" -ne 0 ]; then
        sudo -u cuckoo -i sh "$CRONJOB"
    fi

    # Remove all Virtual Machine related logfiles, we're not interested
    # in keeping those.
    rm -f $(find "$VMBACKUP" -type f|grep "\.log")
}

_setup_vms() {
    # Create directories in the target directory for each directory found in
    # the source directory. Then create a symlink for all .vdi and .sav files
    # and copy over all .vbox files.
    if [ ! -d "$1" ] || [ ! -d "$2" ]; then
        echo "Missing parameter(s) for setup-vms.."
        exit 1
    fi

    local source="$1" target="$2"

    # Create each directory.
    for dirname in $(cd "$source" && find * -type d); do
        sudo -u cuckoo mkdir -p "$target/$dirname"
    done

    # Make symlinks of all files .vdi and .sav files, these are considered
    # readonly files by VirtualBox due to the immutable disk property.
    for filename in $(cd "$source" && find bird*.vdi */*/*.vdi */*/*.sav); do
        sudo -u cuckoo ln -fs "$source/$filename" "$target/$filename"
    done

    # Copy all .vbox files, these may be modified by VirtualBox. In the case
    # that somehow we end up with out of diskspace issues and the updated
    # .vbox files can not be written to disk, then the virtual machine is
    # essentially bricked. These files are only a couple of kilobytes anyway.
    for filename in $(cd "$source" && find */*.vbox); do
        sudo -u cuckoo cp "$source/$filename" "$target/$filename"
    done
}

_setup_vmmount() {
    if [ ! -d "$1" ] || [ ! -d "$2" ]; then
        echo "Missing parameter(s) for setup-vmmount.."
        exit 1
    fi

    local source="$1" target="$2"

    # Unmount just in case it was mounted.
    umount "$target"

    # Calculate the required size for the tmpfs mount. Round up to megabytes.
    REQSIZE="$(du -s "$source"|cut -f1)"
    REQSIZE="$(($REQSIZE/1024+1))M"

    mount -o "size=$REQSIZE,uid=cuckoo,gid=cuckoo" -t tmpfs tmpfs "$target"

    # Copy all files from the backup to the mount.
    sudo -u cuckoo cp -rf "$source/." "$target"
}

_initialize_from_backup() {
    # Initialize our setup from our backup, if available.
    local tmpfs="$1"

    if [ "$tmpfs" -ne 0 ]; then
        # Initialize a mount with all the files from the backup directory.
        _setup_vmmount "$VMBACKUP" "$VMMOUNT"

        # Initialize vms to point to the mount directory.
        _setup_vms "$VMMOUNT" "$VMS"
    else
        # Initialize vms to point to the backup directory.
        _setup_vms "$VMBACKUP" "$VMS"
    fi
}

# Initialize various variables.
MOUNT="/mnt/$MOUNTOS/"
VMS="$BASEDIR/vms/"
VMBACKUP="$BASEDIR/vmbackup/"
VMMOUNT="/home/cuckoo/vmmount/"

# In Upstart scripts the $HOME variable may not have been set. If so, set it.
if [ -z "$HOME" ]; then
    export HOME="/home/cuckoo"
fi

# If $LC_ALL is not set then we force it to en_US.UTF-8, otherwise PostgreSQL
# and possibly others will complain about a missing language.
if [ -z "$LC_ALL" ]; then
    export LC_ALL="en_US.UTF-8"
fi

# First of all, setup the machine with all required packages etc
# if asked to do so. (Or, actually, if not asked to not do).
if [ "$VMCHECKUP" -eq 0 ]; then
    _setup

    # We store this exact configuration so that we can later on recreate
    # the cluster in case that's required. E.g., when VMs break or after
    # a reboot when using tmpfs support (which is actually an instance of
    # VMs breaking).
    cat > /etc/default/cuckoo-setup << EOF
# Direct configuration values.
WIN7="$WIN7"
VMCOUNT="$VMCOUNT"
ISOFILE="$ISOFILE"
SERIALKEY="$SERIALKEY"
TMPFS="$TMPFS"
TAGS="$TAGS"
INTERFACES="$INTERFACES"
DEPENDENCIES="$DEPENDENCIES"
BASEDIR="$BASEDIR"
LONGTERM="$LONGTERM"
CPUCOUNT="$CPUCOUNT"

# Values set based on configuration values.
EGGNAME="$EGGNAME"
MOUNTOS="$MOUNTOS"
WINOS="$WINOS"
EOF
fi

# The mount directory must exist and it must not be empty.
if [ ! -d "$MOUNT" ] || [ -z "$(ls -A "$MOUNT")" ]; then
    mkdir -p "$MOUNT"
    mount -o loop,ro "$ISOFILE" "$MOUNT"
fi

# Remove the vms directory as we don't want broken remainders
# in there later on such as symbolic links.
rm -rf "$VMS"

mkdir -p "$VMS" "$VMBACKUP" "$VMMOUNT"
chown cuckoo:cuckoo "$VMS" "$VMBACKUP" "$VMMOUNT"

# In the case of tmpfs support we first setup the vmmount and all that so to
# recover any VMs that were not actually broken, but were just missing
# symbolic links and some files copied over. At this point, however, we do not
# setup the entire tmpfs thing yet, though, as that would just require a lot
# of file copying even though we might have to do this right again after
# creating new VMs.
_initialize_from_backup 0

# We then create new VMs if required.
_create_virtual_machines

# Initialize all VMs.
_initialize_from_backup "$TMPFS"
