============
Requirements
============

Before proceeding on configuring Cuckoo, you'll need to install some required
software and libraries.

Installing Python libraries
===========================

Cuckoo host components are completely written in Python, therefore make sure to
have an appropriate version installed. For the current release **Python 2.7** is
preferred.

Install the basic dependencies::

    $ sudo apt-get install python python-pip python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg-dev

If you want to use the Django-based web interface, you'll have to install
MongoDB too::

    $ sudo apt-get install mongodb

In order to properly function, Cuckoo requires some dependencies. They can all
be installed through PyPI like this::

    $ sudo pip install -r requirements.txt

`Yara`_ and `Pydeep`_ are *optional* plugins but will have to be installed
manually, so please refer to their websites.

If you want to use KVM it's packaged too and you can install it with the
following command::

    $ sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt

If you want to use XenServer you'll have to install the *XenAPI* Python package::

    $ sudo pip install XenAPI

If you want to use the *mitm* auxiliary module (to intercept SSL/TLS generated
traffic), you need to install `mitmproxy`_. Please refer to its website for
installation instructions.

.. _Yara: http://virustotal.github.io/yara/
.. _Pydeep: https://github.com/kbandla/pydeep
.. _mitmproxy: https://mitmproxy.org/

Virtualization Software
=======================

Despite heavily relying on `VirtualBox`_ in the past, Cuckoo has moved on being
architecturally independent from the virtualization software.
As you will see throughout this documentation, you'll be able to define and
write modules to support any software of your choice.

For the sake of this guide we will assume that you have VirtualBox installed
(which still is the default option), but this does **not** affect anyhow the
execution and general configuration of the sandbox.

You are completely responsible for the choice, configuration and execution of
your virtualization software, therefore please refrain from asking for help on
it in our channels and lists: refer to the software's official documentation
and support.

Assuming you decide to go for VirtualBox, you can get the proper package for
your distribution at the `official download page`_.
The installation of VirtualBox is outside the scope of this documentation, if
you are not familiar with it please refer to the `official documentation`_.

.. _VirtualBox: http://www.virtualbox.org
.. _official download page: https://www.virtualbox.org/wiki/Linux_Downloads
.. _official documentation: https://www.virtualbox.org/wiki/Documentation

Installing Tcpdump
==================

In order to dump the network activity performed by the malware during
execution, you'll need a network sniffer properly configured to capture
the traffic and dump it to a file.

By default Cuckoo adopts `tcpdump`_, the prominent open source solution.

Install it on Ubuntu::

    $ sudo apt-get install tcpdump

Tcpdump requires root privileges, but since you don't want Cuckoo to run as root
you'll have to set specific Linux capabilities to the binary::

    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

You can verify the results of last command with::

    $ getcap /usr/sbin/tcpdump
    /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

If you don't have `setcap` installed you can get it with::

    $ sudo apt-get install libcap2-bin

Or otherwise (**not recommended**) do::

    $ sudo chmod +s /usr/sbin/tcpdump

Please keep in mind that even the `setcap` method is definitely not perfectly
safe if the system has other users which are potentially untrusted. We recommend
to run Cuckoo on a dedicated system or a trusted environment where the
privileged tcpdump execution is contained otherwise.

.. _tcpdump: http://www.tcpdump.org

Installing Volatility
=====================

Volatility is an optional tool to do forensic analysis on memory dumps.
In combination with Cuckoo, it can automatically provide additional visibility
into deep modifications in the operating system as well as detect the presence
of rootkit technology that escaped the monitoring domain of Cuckoo's analyzer.

In order to function properly, Cuckoo requires at least version 2.3 of
Volatility.
You can get it from the `official repository`_.

See the volatility documentation for detailed instructions on how to install it.

.. _official repository: https://github.com/volatilityfoundation
