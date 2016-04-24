=========
Utilities
=========

Cuckoo comes with a set of pre-built utilities to automate several common
tasks. Before these utilities could be found in the ``utils/`` directory but
since then we have moved to ``Cuckoo Apps``.

Cuckoo Apps
===========

A ``Cuckoo App`` is essentially just a Cuckoo sub-command. There exist a
couple of Cuckoo Apps, each with their own functionality. It is important to
note that each Cuckoo App can be invoked in the same way. Following are some
examples::

    $ cuckoo submit --help
    $ cuckoo api --help
    $ cuckoo clean --help

In these examples we provided the ``--help`` parameter which shows the
functionality and all available parameters for the particular Cuckoo App.

Submission Utility
==================

Submits samples to analysis. This tool is described in :doc:`submit`.

Web Utility
===========

Cuckoo's web interface. This tool is described in :doc:`web`.

Processing Utility
==================

.. versionchanged:: 2.0-rc2
    We used to have longstanding issues with ``./utils/process.py`` randomly
    freezing up and ``./utils/process2.py`` only being able to handle
    PostgreSQL-based databases. These two commands have now been merged into
    one Cuckoo App and no longer shows signs of said issues or limitations.

For bigger Cuckoo setups it is recommended to separate the results processing
from the Cuckoo analyses. It is also possible to re-generate a Cuckoo report,
this is mostly used while developing and debugging Cuckoo Signatures.

In order to do results processing in a separate process one has to disable the
``process_results`` configuration item in ``$CWD/conf/cuckoo.conf`` by setting
the value to ``off``. Then a Cuckoo Processing instance has to be started,
this can be done as follows::

    $ cuckoo process instance1

If one Cuckoo Processing instance is not enough to handle all the incoming
analyses, simply create a second, third, or fourth instance::

    $ cuckoo process instance2

In order to re-generate a Cuckoo report of an analysis task, use the ``-r``
switch::

    $ cuckoo process -r 1

For more information see also the help on this ``Cuckoo App``::

    $ cuckoo process --help
    Usage: cuckoo process [OPTIONS] [INSTANCE]

    Process raw task data into reports.

    Options:
    -r, --report INTEGER    Re-generate a report
    -m, --maxcount INTEGER  Maximum number of analyses to process
    -d, --debug             Enable verbose logging
    -q, --quiet             Only log warnings and critical messages
    --help                  Show this message and exit.

    In automated mode an instance name is required!

Community Download Utility
==========================

This ``Cuckoo App`` downloads Cuckoo Signatures, the latest monitoring
binaries, and other goodies from the `Cuckoo Community Repository`_ and
installs them in your ``CWD``.

To get all the latest and greatest from the Cuckoo Community simply execute
as follows and wait until it finishes - it currently doesn't have any progress
indication::

    $ cuckoo community

For more usage see as follows::

    $ cuckoo community --help
    Usage: cuckoo community [OPTIONS]

    Utility to fetch supplies from the Cuckoo Community.

    Options:
    -f, --force              Overwrite existing files
    -b, --branch TEXT        Specify a different community branch rather than
                             master
    --file, --filepath PATH  Specify a local copy of a community .tar.gz file
    --help                   Show this message and exit.

.. _`Cuckoo Community Repository`: https://github.com/cuckoosandbox/community

Database migration utility
==========================

.. deprecated:: 2.0-rc2
    This will be ported into a Cuckoo App in an upcoming update.

This utility is developed to migrate your data between Cuckoo's release.
It's developed on top of the `Alembic`_ framework and it should provide data
migration for both SQL database and Mongo database.
This tool is already described in :doc:`../installation/upgrade`.

.. _`Alembic`: http://alembic.readthedocs.org/en/latest/

Stats utility
=============

.. deprecated:: 2.0-rc2
    This utility will not be ported to a Cuckoo App as this information can
    also be retrieved through both the Cuckoo API as well as the Cuckoo Web
    Interface.

This is a really simple utility which prints some statistics about processed
samples::

    $ ./utils/stats.py

    1 samples in db
    1 tasks in db
    pending 0 tasks
    running 0 tasks
    completed 0 tasks
    recovered 0 tasks
    reported 1 tasks
    failed_analysis 0 tasks
    failed_processing 0 tasks
    roughly 32 tasks an hour
    roughly 778 tasks a day

Machine utility
===============

.. deprecated:: 2.0-rc2
    This utility will be ported to a Cuckoo App in an upcoming Cuckoo update.

The machine.py utility is designed to help you automatize the configuration of
virtual machines in Cuckoo.
It takes a list of machine details as arguments and write them in the specified
configuration file of the machinery module enabled in *cuckoo.conf*.
Following are the available options::

    $ ./utils/machine.py -h
    usage: machine.py [-h] [--debug] [--add] [--delete] [--ip IP]
                      [--platform PLATFORM] [--tags TAGS] [--interface INTERFACE]
                      [--snapshot SNAPSHOT] [--resultserver RESULTSERVER]
                      vmname

    positional arguments:
      vmname                Name of the Virtual Machine.

    optional arguments:
      -h, --help            show this help message and exit
      --debug               Debug log in case of errors.
      --add                 Add a Virtual Machine.
      --delete              Delete a Virtual Machine.
      --ip IP               Static IP Address.
      --platform PLATFORM   Guest Operating System.
      --tags TAGS           Tags for this Virtual Machine.
      --interface INTERFACE
                            Sniffer interface for this machine.
      --snapshot SNAPSHOT   Specific Virtual Machine Snapshot to use.
      --resultserver RESULTSERVER
                            IP:Port of the Result Server.

Distributed scripts
===================

.. deprecated:: 2.0-rc2
    Distributed Cuckoo has not been properly integrated yet in the Cuckoo
    Package. When that happens functionality from these scripts will likely
    be moved elsewhere.

There are a couple of shell scripts used to automate distributed utility:

 * "start-distributed" is used to start distributed Cuckoo
 * "stop-distributed" is used to stop distributed Cuckoo

Mac OS X Bootstrap scripts
==========================

.. deprecated:: 2.0-rc2
    These files will be moved elsewhere in an upcoming update and so should
    any documentation that references these scripts.

A couple of bootstrap scripts used for Mac OS X analysis are located in
*utils/darwin* folder, they are used to bootstrap the guest and host system for
Mac OS X malware analysis.
Some settings are defined as constants inside them, so it is suggested to have a
look at them and configure them for your needs.

SMTP Sinkhole
=============

.. deprecated:: 2.0-rc2
    Whether this will be integrated as a Cuckoo App has yet to be determined.

The smtp_sinkhole.py utility is designed to provide an easy to use SMTP sinkhole
to catch all the emails going out of virtual machines network.
This is typically used to dump all emails when you run an analysis of sample
used for spam purposes. You can use it also to prevent sending spam on
internet.
Following are the available options::

    $ ./utils/smtp_sinkhole.py -h
    usage: smtp_sinkhole.py [host [port]]

    SMTP Sinkhole

    positional arguments:
      host
      port

    optional arguments:
      -h, --help  show this help message and exit
      --dir DIR   Directory used to dump emails.

By default, if you run it without arguments, it will listen for incoming mails
on localhost port 1025.
Yoy can bind it on different address and port, as in the following example::

    $ ./utils/smtp_sinkhole.py 192.168.56.1 1025

If you want to save the dumped emails to disk, just use the *--dir* argument and
specify an existent directory where save them, as in the following example::

    $ ./utils/smtp_sinkhole.py --dir /home/dumpmail

You have to use iptables to route all mails generated from your analysis virtual
machine network to the sinkhole script, for example if 192.168.56.0/24 is the
address of your virtual network and smtp_sinkhole.py is listening on
192.168.56.1 port 1025 you can use the following command::

    $ sudo iptables -t nat -A PREROUTING -i vboxnet0 -p tcp -m tcp --dport 25 -j REDIRECT --to-ports 1025

Setup script
============

.. deprecated:: 2.0-rc2
    This script requires a major rewrite given it operates on the legacy
    variant of Cuckoo.

Cuckoo setup script is a tool to setup a whole Cuckoo environment on a Debian
based OS (i.e. Ubuntu or Debian).
Actually it is a working in progress, but it is suggested to give it a try!
It is located in *utils/setup.sh* and it is configured by some constants, so
you should edit it if you want to customize the behaviour.
