=========
Utilities
=========

Cuckoo comes with a set of pre-built utilities to automate several common
tasks.
You can find them under the "utils" folder.

Submission Utility
==================

Submits samples to analysis. This tool is already described in :doc:`submit`.

Web Utility
===========

Cuckoo's web interface. This tool is already described in :doc:`submit`.

Processing Utility
==================

Run the results processing engine and optionally the reporting engine (run
all reports) on an already available analysis folder, in order to not re-run
the analysis if you want to re-generate the reports for it.
This is used mainly in debugging and developing Cuckoo.
For example if you want run again the report engine for analysis number 1::

    $ ./utils/process.py 1

If you want to re-generate the reports::

    $ ./utils/process.py --report 1

Following are the usage options::

    $ ./utils/process.py -h
    usage: process.py [-h] [-d] [-r] [-p PARALLEL] [-u USER] [-m MODULES] id

    positional arguments:
      id                    ID of the analysis to process (auto for continuous
                            processing of unprocessed tasks).

    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           Display debug messages
      -r, --report          Re-generate report
      -p PARALLEL, --parallel PARALLEL
                            Number of parallel threads to use (auto mode only).
      -u USER, --user USER  Drop user privileges to this user
      -m MODULES, --modules MODULES
                            Path to signature and reporting modules - overrides
                            default modules path.

As best practice we suggest to adopt the following configuration if you are
running Cuckoo with many virtual machines:

    * Run a stand alone process.py in auto mode (you choose the number of parallel threads)
    * Disable Cuckoo reporting in cuckoo.conf (set process_results to off)

This could increase the performance of your system because the reporting is not
yet demanded to Cuckoo.

With Cuckoo 2 a new processing utility was introduced, it is more stable and
with better performance. It is dubbed *process2.py*, following are the usage
options::

    $ ./utils/process2.py -h
    usage: process2.py [-h] [-d] [-u USER] [-m MODULES] instance

    positional arguments:
      instance              Task processing instance.

    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           Display debug messages
      -u USER, --user USER  Drop user privileges to this user
      -m MODULES, --modules MODULES
                            Path to signature and reporting modules - overrides
                            default modules path.

Community Download Utility
==========================

This utility downloads signatures from `Cuckoo Community Repository`_ and installs
specific additional modules in your local setup and for example update it with
all the latest available signatures.
Following are the usage options::

    $ ./utils/community.py -h

    usage: community.py [-h] [-a] [-s] [-p] [-m] [-r] [-f] [-w] [-b BRANCH]

    optional arguments:
      -h, --help            show this help message and exit
      -a, --all             Download everything
      -s, --signatures      Download Cuckoo signatures
      -p, --processing      Download processing modules
      -m, --machinery       Download machine managers
      -n, --analyzer        Download analyzer modules
      -g, --agent           Download agent modules
      -r, --reporting       Download reporting modules
      -f, --force           Install files without confirmation
      -w, --rewrite         Rewrite existing files
      -b BRANCH, --branch BRANCH
                            Specify a different branch

*Example*: install all available signatures::

    $ ./utils/community.py --signatures --force

.. _`Cuckoo Community Repository`: https://github.com/cuckoosandbox/community

Database migration utility
==========================

This utility is developed to migrate your data between Cuckoo's release.
It's developed on top of the `Alembic`_ framework and it should provide data
migration for both SQL database and Mongo database.
This tool is already described in :doc:`../installation/upgrade`.

.. _`Alembic`: http://alembic.readthedocs.org/en/latest/

Stats utility
=============

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

There are a couple of shell scripts used to automate distributed utility:

 * "start-distributed" is used to start distributed Cuckoo
 * "stop-distributed" is used to stop distributed Cuckoo

Mac OS X Bootstrap scripts
==========================

A couple of bootstrap scripts used for Mac OS X analysis are located in
*utils/darwin* folder, they are used to bootstrap the guest and host system for
Mac OS X malware analysis.
Some settings are defined as constants inside them, so it is suggested to have a
look at them and configure them for your needs.

SMTP Sinkhole
=============

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

Cuckoo setup script is a tool to setup a whole Cuckoo environment on a Debian
based OS (i.e. Ubuntu or Debian).
Actually it is a working in progress, but it is suggested to give it a try!
It is located in *utils/setup.sh* and it is configured by some constants, so
you should edit it if you want to customize the behaviour.
