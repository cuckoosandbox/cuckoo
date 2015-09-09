=========
Utilities
=========

Cuckoo comes with a set of pre-built utilities to automate several common
tasks.
You can find them under the "utils" folder.

.. _cleanup-utility:

Cleanup utility
===============

.. deprecated:: 1.2

    Use :ref:`./cuckoo.py --clean <cuckoo-clean>` instead which *also* takes
    care of cleaning sample and task information from MySQL and PostgreSQL
    databases.

If you want to delete all history, analysis, data and begin again from the first
task you need the clean.sh utility.

.. note::

    Running clean.sh will delete: analysis results, binaries, SQLite database (if used) and logs.

To clean your setup, run::

    $ ./utils/clean.sh

This utility is designed to be used with Cuckoo (including API and web interface)
not running.

If you are using a custom database (MySQL, PostgreSQL or SQLite in custom
location) clean.sh doesn't clean it, you have to take care of that.

If you are using the MongoDB reporting module clean.sh does **not** clean your
database, you have to take care of that.

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

    usage: process.py [-h] [-d] [-r] [-p PARALLEL] id

    positional arguments:
      id                    ID of the analysis to process (auto for continuous
                            processing of unprocessed tasks).

    optional arguments:
      -h, --help            show this help message and exit
      -d, --debug           Display debug messages
      -r, --report          Re-generate report
      -p PARALLEL, --parallel PARALLEL
                            Number of parallel threads to use (auto mode only).

As best practice we suggest to adopt the following configuration if you are
running Cuckoo with many virtual machines:

    * Run a stand alone process.py in auto mode (you choose the number of parallel threads)
    * Disable Cuckoo reporting in cuckoo.conf (set process_results to off)

This could increase the performance of your system because the reporting is not
yet demanded to Cuckoo.

Community Download Utility
==========================

This utility downloads signatures from `Cuckoo Community Repository`_ and installs
specific additional modules in your local setup and for example update id with
all the latest available signatures.
Following are the usage options::

    $ ./utils/community.py -h

    usage: community.py [-h] [-a] [-s] [-p] [-m] [-r] [-f] [-w] [-b BRANCH]

    optional arguments:
      -h, --help            show this help message and exit
      -a, --all             Download everything
      -s, --signatures      Download Cuckoo signatures
      -p, --processing      Download processing modules
      -m, --machinemanagers
                            Download machine managers
      -r, --reporting       Download reporting modules
      -f, --force           Install files without confirmation
      -w, --rewrite         Rewrite existing files
      -b BRANCH, --branch BRANCH
                            Specify a different branch

*Example*: install all available signatures::

  $ ./utils/community.py --signatures --force

.. _`Cuckoo Community Repository`: https://github.com/cuckoobox/community

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
  usage: machine.py [-h] [--debug] [--add] [--ip IP] [--platform PLATFORM]
                  [--tags TAGS] [--interface INTERFACE] [--snapshot SNAPSHOT]
                  [--resultserver RESULTSERVER]
                  vmname

  positional arguments:
    vmname                Name of the Virtual Machine.

  optional arguments:
    -h, --help            show this help message and exit
    --debug               Debug log in case of errors.
    --add                 Add a Virtual Machine.
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