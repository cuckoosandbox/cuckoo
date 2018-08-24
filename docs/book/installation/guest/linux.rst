=========================
Installing the Linux host
=========================

First prepare the networking for your machinery platform on the host side.
If you use VirtualBox with e.g. host-only interfaces and you have a
``vboxnet0`` interface, you do not need to install additional dependencies.

.. This has not been tested recently:

If you use QEMU, you may need to install additional
dependencies on the host::

    $ sudo apt install uml-utilities bridge-utils

Next, get the list of virtual machines for which to configure the interface
from ``conf/qemu.conf``.
For example, ``ubuntu_x32``, ``ubuntu_x64``, ``ubuntu_arm``, ``ubuntu_mips``,
``ubuntu_mipsel``, et cetera.
For each VM, preconfigure a network tap interfaces on the host, required to
avoid have to start as root, e.g.::

    $ sudo tunctl -b -u cuckoo -t tap_ubuntu_x32
    $ sudo ip link set tap_ubuntu_x32 master br0
    $ sudo ip link set dev tap_ubuntu_x32 up
    $ sudo ip link set dev br0 up

    $ sudo tunctl -b -u cuckoo -t tap_ubuntu_x64
    $ sudo ip link set tap_ubuntu_x64 master br0
    $ sudo ip link set dev tap_ubuntu_x64 up
    $ sudo ip link set dev br0 up

**Note that if you run Cuckoo as a different user, replace ``cuckoo`` after -u
with your user.**


Preparing x32/x64 Ubuntu 18.04 Linux guests
===========================================

Ensure the agent automatically starts. The easiest way is to add it to crontab::

    $ sudo crontab -e
    @reboot python /path/to/agent.py

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

Patch the SystemTap tapset, so that the Cuckoo analyzer can properly parse the
output::

    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/expand_execve_envp.patch
    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/escape_delimiters.patch
    $ sudo patch /usr/share/systemtap/tapset/linux/sysc_execve.stp < expand_execve_envp.patch
    $ sudo patch /usr/share/systemtap/tapset/uconversions.stp < escape_delimiters.patch

Compile the kernel extension::

    $ wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/strace.stp
    $ sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v

Once the compilation finishes you should see the file ``stap_.ko`` in the same
folder. You will now be able to test the STAP kernel extension as follows::

    $ sudo staprun -v ./stap_.ko

Output should be something like as follows::

    staprun:insert_module:x Module stap_ inserted from file path_to_stap_.ko

The ``stap_.ko`` file should be placed in /root/.cuckoo::

    $ sudo mkdir /root/.cuckoo
    $ sudo mv stap_.ko /root/.cuckoo/

Disable the firewall inside of the VM, if it exists::

    $ sudo ufw disable

Disable NTP inside of the VM::

    $ sudo timedatectl set-ntp off

Optional - preinstalled remove software and configurations::

    $ sudo apt-get purge update-notifier update-manager update-manager-core ubuntu-release-upgrader-core
    $ sudo apt-get purge whoopsie ntpdate cups-daemon avahi-autoipd avahi-daemon avahi-utils
    $ sudo apt-get purge account-plugin-salut libnss-mdns telepathy-salut

It is recommended to configure the Linux guest with a static IP addresses.
Make sure the machine entry in the configuration has the correct IP address and
has the ``platform`` variable set to ``linux``.
Create a snapshot once the VM has been configured.
It is now ready for analysis!
