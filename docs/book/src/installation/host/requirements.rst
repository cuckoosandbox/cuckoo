============
Requirements
============

Before proceeding on configuring Cuckoo, you'll need to install some required
softwares and libraries.

Installing Python libraries
===========================

Cuckoo host components are completely written in Python, therefore make sure to
have an appropriate version installed. For current release Python 2.6 or 2.7 are
preferred.

Install Python on Ubuntu::

    $ sudo apt-get install python

In order to properly execute, Cuckoo really just needs the default installation
of Python.

However several additional features and modules require some Python libraries
you will need to install in order to make them run successfully.
We suggest you to install all of them so that you can take advantage of the
project at its full potential.

    * `Magic`_ (Highly Recommended): for identifying files' formats (otherwise use "file" command line utility)
    * `Pyssdeep`_ (Recommended): for calculating ssdeep fuzzy hash of files.
    * `Dpkt`_ (Highly Recommended): for extracting relevant information from PCAP files.
    * `Mako`_ (Highly Recommended): for rendering the HTML reports and the web interface.
    * `Pymongo`_ (Optional): for storing the results in a MongoDB database.
    * `Yara`_ and Yara Python (Optional): for matching Yara signatures.
    * `Libvirt`_ (Optional): for using the KVM module.

Some of them are packaged in GNU/Linux Ubuntu and you can install them with the following command::

    $ sudo apt-get install python-magic python-dpkt python-mako python-pymongo

If want to use KVM it's packaged too and you can install it with the following command::

	$ sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils

For the rest refer to their websites.

.. _Magic: http://www.darwinsys.com/file/
.. _Dpkt: http://code.google.com/p/dpkt/
.. _Mako: http://www.makotemplates.org
.. _Pyssdeep: http://code.google.com/p/pyssdeep/
.. _Pymongo: http://pypi.python.org/pypi/pymongo/
.. _Yara: http://code.google.com/p/yara-project/
.. _Libvirt: http://www.libvirt.org

Virtualization Software
=======================

Despite heavily relying on `VirtualBox`_ in the past, Cuckoo has moved on being
architecturally independent from the virtualization software.
As you will see throughout this documentation, you'll be able to define and write
modules to support any software of your choice.

For the sake of this guide we will assume that you have VirtualBox installed
(which still is the default option), but this does **not** affect anyhow the
execution and general configuration of the sandbox.

You are completely responsible for the choice, configuration and execution of
your virtualization software, therefore please hold from asking help on it in our
channels and lists: refer to the software's official documentation and support.

Assuming you decide to go for VirtualBox, you can get the proper package for
your distribution at the `official download page`_.
The installation of VirtualBox is not in the purpose of this documentation, if you
are not familiar with it please refer to the `official documentation`_.

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

Or otherwise (**not recommended**) do::

    $ sudo chmod +s /usr/sbin/tcpdump

.. _tcpdump: http://www.tcpdump.org

