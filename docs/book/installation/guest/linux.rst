=========================
Installing the Linux host
=========================

Install dependencies on host::

    $ sudo apt-get install uml-utilities bridge-utils

Preconfigure network tap interfaces on host, required to avoid have to start
as root::

    Get list of virtual machines to configure interface per vm from conf/qemu.conf

    Example:
        machines = ubuntu_x32, ubuntu_x64, ubuntu_arm, ubuntu_mips, ubuntu_mipsel

You should preconfigure network interface for all of them, they all should
have ``tap`` prefix::

    $ sudo tunctl -b -u cuckoo -t tap_ubuntu_x32
    $ sudo ip link set tap_ubuntu_x32 master br0
    $ sudo ip link set dev tap_ubuntu_x32 up
    $ sudo ip link set dev br0 up

    $ sudo tunctl -b -u cuckoo -t tap_ubuntu_x64
    $ sudo ip link set tap_ubuntu_x64 master br0
    $ sudo ip link set dev tap_ubuntu_x64 up
    $ sudo ip link set dev br0 up

The following instructions are only for x32/x64 ubuntu 17.04 linux guests
=========================================================================

** Note if you run cuckoo with with no cuckoo user, replace cuckoo after -u to
your user **

Add agent to autorun, the easier way is to add it to crontab::

    $ sudo crontab -e
    @reboot python path_to_agent.py

Install dependencies inside of the virtual machine::

    $ sudo apt-get install systemtap gcc patch linux-headers-$(uname -r)

Install kernel debugging symbols::

    $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622

    $ codename=$(lsb_release -cs)
    $ sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
      deb http://ddebs.ubuntu.com/ ${codename}          main restricted universe multiverse
      #deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
      deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
      deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
    EOF

    $ sudo apt-get update
    $ sudo apt-get install linux-image-$(uname -r)-dbgsym

Patch SystemTap tapset (this will change in the future)::

    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/expand_execve_envp.patch
    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/escape_delimiters.patch
    $ sudo patch /usr/share/systemtap/tapset/linux/sysc_execve.stp < expand_execve_envp.patch
    $ sudo patch /usr/share/systemtap/tapset/uconversions.stp < escape_delimiters.patch

Compile Kernel extension::

    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/strace.stp
    $ sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v

Once the compilation finishes you should see the file ``stap_.ko`` in the same
folder. You will now be able to test the STAP kernel extension as follows.

Test Kernel extension::

    $ sudo staprun -v ./stap_.ko

Output should be something like as follows::

    staprun:insert_module:x Module stap_ inserted from file path_to_stap_.ko

The ``stap_.ko`` file should be placed in /root/.cuckoo::

    $ sudo mkdir /root/.cuckoo
    $ sudo mv stap_.ko /root/.cuckoo/

Disable firewall inside of the vm, if exists::

    $ sudo ufw disable

Disable NTP inside of the vm::

    $ sudo timedatectl set-ntp off

Optional - preinstalled remove software and configurations::

    $ sudo apt-get purge update-notifier update-manager update-manager-core ubuntu-release-upgrader-core
    $ sudo apt-get purge whoopsie ntpdate cups-daemon avahi-autoipd avahi-daemon avahi-utils
    $ sudo apt-get purge account-plugin-salut libnss-mdns telepathy-salut
