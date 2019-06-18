============
Requirements
============

Before proceeding to installing and configuring Cuckoo, you'll need to install
some required software packages and libraries.

Installing Python libraries (on Ubuntu/Debian-based distributions)
==================================================================

The Cuckoo host components is completely written in Python, therefore it is
required to have an appropriate version of Python installed. At this point we
only fully support **Python 2.7**. Older version of Python and Python 3
versions are not supported by us (although Python 3 support is on our TODO
list with a low priority).

The following software packages from the apt repositories are required to get
Cuckoo to install and run properly::

    $ sudo apt-get install python python-pip python-dev libffi-dev libssl-dev
    $ sudo apt-get install python-virtualenv python-setuptools
    $ sudo apt-get install libjpeg-dev zlib1g-dev swig

In order to use the Django-based Web Interface, MongoDB is required::

    $ sudo apt-get install mongodb

In order to use PostgreSQL as database (our recommendation), PostgreSQL will
have to be installed as well::

    $ sudo apt-get install postgresql libpq-dev

`Pydeep`_ is an *optional* plugin that can be installed manually. A Link is provided for convenience:
* `pydeep install`_ - note: the ``libfuzzy-dev`` package is required for
  pydeep but at the time of writing, was not listed in the official
  documentation.

If you want to use KVM as machinery module you will have to install KVM::

    $ sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt

If you want to use XenServer you'll have to install the *XenAPI* Python package::

    $ sudo pip install XenAPI

If you want to use the *mitm* auxiliary module (to intercept SSL/TLS generated
traffic), you need to install `mitmproxy`_. Please refer to its website for
installation instructions. Please note that the latest version of
``mitmproxy`` requires Python 3.6 or higher and therefore it's required to
install it within a separate ``virtualenv`` to isolate it and its requirements
from Cuckoo's Python 2.7 environment. After installing mitmproxy in a separate
virtualenv, include its binary path in the Cuckoo configuration, e.g.,
``/tmp/mitmproxy3/bin/mitmdump`` if the virtualenv is ``/tmp/mitmproxy3``.

.. _Yara: https://github.com/plusvic/yara
.. _Pydeep: https://github.com/kbandla/pydeep
.. _mitmproxy: https://mitmproxy.org/
.. _pydeep install: https://github.com/kbandla/pydeep/blob/master/INSTALL

Installing Python libraries (on Mac OS X)
=========================================

This is mostly the same as the installation on Ubuntu/Debian, except that
we'll be using the ``brew`` package manager. Install all the required
dependencies as follows (this list is WIP)::

    $ brew install libmagic cairo pango openssl

In addition to that you'll also want to expose the openssl header files in the
standard GCC/Clang include directory, so that ``yara-python`` may compile
successfully. This can be done `as follows`_::

    $ cd /usr/local/include
    $ ln -s ../opt/openssl/include/openssl .

.. _as follows: https://www.anintegratedworld.com/mac-osx-fatal-error-opensslsha-h-file-not-found/

Installing Python libraries (on Windows 7)
==========================================

To be documented.

Virtualization Software
=======================

Cuckoo Sandbox supports most Virtualization Software solutions. As you will
see throughout the documentation, Cuckoo has been setup to remain as modular
as possible and in case integration with a piece of software is missing this
could be easily added.

For the sake of this guide we will assume that you have VirtualBox installed
(which is the default), but this does **not** affect the execution and general
configuration of the sandbox.

You are completely responsible for the choice, configuration, and execution of
your virtualization software. Please read our extensive documentation and FAQ
before reaching out to us with questions on how to set Cuckoo up.

Assuming you decide to go for VirtualBox, you can get the proper package for
your distribution at the `official download page`_. Please find following the
commands to install the latest version of VirtualBox on your Ubuntu LTS
machine. Note that Cuckoo supports VirtualBox 4.3, 5.0, 5.1, and 5.2::

    $ echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
    $ wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
    $ sudo apt-get update
    $ sudo apt-get install virtualbox-5.2

For more information on VirtualBox, please refer to the
`official documentation`_.

.. _VirtualBox: http://www.virtualbox.org
.. _official download page: https://www.virtualbox.org/wiki/Linux_Downloads
.. _official documentation: https://www.virtualbox.org/wiki/Documentation

Installing tcpdump
==================

In order to dump the network activity performed by the malware during
execution, you'll need a network sniffer properly configured to capture
the traffic and dump it to a file.

By default Cuckoo adopts `tcpdump`_, the prominent open source solution.

Install it on Ubuntu::

    $ sudo apt-get install tcpdump apparmor-utils
    $ sudo aa-disable /usr/sbin/tcpdump

Note that the ``AppArmor`` profile disabling (the ``aa-disable`` command) is
only required when using the default ``CWD`` directory as AppArmor would
otherwise prevent the creation of the actual PCAP files (see also
:ref:`tcpdump_permission_denied`).

For Linux platforms with AppArmor disabled (e.g., Debian) the following
command will suffice to install `tcpdump`_::

    $ sudo apt-get install tcpdump

Tcpdump requires root privileges, but since you don't want Cuckoo to run as
root you'll have to set specific Linux capabilities to the binary::

    $ sudo groupadd pcap
    $ sudo usermod -a -G pcap cuckoo
    $ sudo chgrp pcap /usr/sbin/tcpdump
    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

You can verify the results of the last command with::

    $ getcap /usr/sbin/tcpdump
    /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

If you don't have `setcap` installed you can get it with::

    $ sudo apt-get install libcap2-bin

Or otherwise (**not recommended**) do::

    $ sudo chmod +s /usr/sbin/tcpdump

Please keep in mind that even the `setcap` method is not perfectly safe (due
to potential security vulnerabilities) if the system has other users which are
potentially untrusted. We recommend to run Cuckoo on a dedicated system or a
trusted environment where the privileged tcpdump execution is contained
otherwise.

.. _tcpdump: http://www.tcpdump.org

Installing Volatility
=====================

Volatility is an optional tool to do forensic analysis on memory dumps. In
combination with Cuckoo, it can automatically provide additional visibility
into deep modifications in the operating system as well as detect the presence
of rootkit technology that escaped the monitoring domain of Cuckoo's analyzer.

In order to function properly, Cuckoo requires at least version 2.3 of
Volatility, but recommends the latest version, Volatility 2.5. You can
download it from their `official repository`_.

See the volatility documentation for detailed instructions on how to install it.

.. _official repository: https://github.com/volatilityfoundation

Installing M2Crypto
===================

Currently the ``M2Crypto`` library is only supported when `SWIG`_ has been
installed. On Ubuntu/Debian-like systems this may be done as follows::

    $ sudo apt-get install swig

If ``SWIG`` is present on the system one may install ``M2Crypto`` as follows::

    $ sudo pip install m2crypto==0.24.0

.. _SWIG: http://www.swig.org/

Installing guacd
================

``guacd`` is an optional service that provides the translation layer for RDP,
VNC, and SSH for the remote control functionality in the Cuckoo web interface.

Without it, remote control won't work. Versions 0.9.9 and up will work, but we
recommend installing the latest version. On an Ubuntu 17.04 machine the
following command will install version ``0.9.9-2``::

    $ sudo apt install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd

If you only want RDP support you can skip the installation of the
``libguac-client-vnc0`` and ``libguac-client-ssh0`` packages.

If you are using an older distribution or you just want to use the latest
version (our recommendation), the following will build the latest version
(``0.9.14``) from source::

    $ sudo apt -y install libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev libfreerdp-dev
    $ mkdir /tmp/guac-build && cd /tmp/guac-build
    $ wget https://www.apache.org/dist/guacamole/0.9.14/source/guacamole-server-0.9.14.tar.gz
    $ tar xvf guacamole-server-0.9.14.tar.gz && cd guacamole-server-0.9.14
    $ ./configure --with-init-dir=/etc/init.d
    $ make && sudo make install && cd ..
    $ sudo ldconfig
    $ sudo /etc/init.d/guacd start

When installing from source, make sure you don't have another version of any
of the ``libguac-`` libraries installed from your package manager or you might
experience issues due to incompatibilities which can crash guacd.

Note that the `VirtualBox Extension Pack`_ must also be installed to take
advantage of the Cuckoo Control functionality exposed by Guacamole.

.. _VirtualBox Extension Pack: https://www.virtualbox.org/wiki/Downloads
