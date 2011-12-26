============
Requirements
============

Before proceeding on configuring Cuckoo, you'll need to install some required
software and libraries.

Installing Python libraries
===========================

Cuckoo host components are completely written in Python, therefore make sure to
have an appropriate version installed. For current release Python 2.6 or 2.7 are
preferred.

Install Python on Ubuntu::

    $ sudo apt-get install python

Cuckoo makes use of several libraries which include:

    * `Magic`_: for detecting file types.
    * `Dpkt`_: for extracting relevant information from PCAP files.
    * `Mako`_: for rendering the HTML reports and the web interface.

On Ubuntu you can install all of them with the following command::

    $ sudo apt-get install python-magic python-dpkt python-mako

On different distributions refer to the provided official homepage to retrieve
other installers or sources.

Other optional libraries, which do not affect Cuckoo's execution, include:

    * `Pyssdeep`_: for calculating ssdeep fuzzy hash of files.

.. _Magic: http://www.darwinsys.com/file/
.. _Dpkt: http://code.google.com/p/dpkt/
.. _Mako: http://www.makotemplates.org
.. _Pyssdeep: http://code.google.com/p/pyssdeep/

Installing VirtualBox
=====================

At current stage, Cuckoo heavily relies on `VirtualBox`_ as it's unique
virtualization engine.

Despite being often packaged by all GNU/Linux distributions, you are encouraged
to download and install the latest version from the official website. The reason
behind this choice is that packaged versions of VirtualBox (called OSE)
generally have some limitations or adjustments in order to meet requirements of
the GNU GPL license.

You can get the proper package for your distribution at the `official download
page`_.

The installation of VirtualBox is not in purposes of this documentation, if you
are not familiar with it please refer to the `official documentation`_.

.. _VirtualBox: http://www.virtualbox.org
.. _official download page: https://www.virtualbox.org/wiki/Linux_Downloads
.. _official documentation: https://www.virtualbox.org/wiki/Documentation

Installing Tcpdump
==================

By default Cuckoo makes use of VirtualBox's embedded network tracing
functionalities, but in some cases or some network configurations you might need
to adopt an external network sniffer.

If you intend to use VirtualBox's own network trace, you can skip this section.

The best choice for packet interception is `tcpdump`_ of course.

Install it on Ubuntu::

    $ sudo apt-get install tcpdump

Tcpdump requires root privileges, but since you don't want Cuckoo to run as root
you'll have to set specific Linux capabilities to the binary::

    $ sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

You can verify the results of last command with::

    $ getcap /usr/sbin/tcpdump 
    /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

.. _tcpdump: http://www.tcpdump.org

