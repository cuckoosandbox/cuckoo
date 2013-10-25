=========
Utilities
=========

Cuckoo comes with a set of pre-built utilities to automatize several common
tasks.
You can find them in "utils" folder.

Cleanup utility
===============

If you want to delete all history, analysis, data and begin again from the first
task you need clean.sh utility.

.. note::

    Running clean.sh will delete: analysis results, binaries, SQLite database (if used) and logs.

To clean your setup, run::

    $ ./utils/clean.sh

This utility is designed to be used with Cuckoo (including API and web interface)
not running.

If you are using a custom database (MySQL, PostgreSQL or SQLite in custom
location) clean.sh doesn't clean it, you have to take care of that.

Submission Utility
==================

Submits sample to analysis. This tool is already described in :doc:`submit`.

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

Community Download Utility
==========================

This utility downloads signatures from `Cuckoo Community Repository`_ and installs
specific additional modules in your local setup and for example update id with
all the latest available signatures.
Following are the usage options::

    $ ./utils/community.py

    usage: community.py [-h] [-a] [-s] [-p] [-m] [-r] [-f] [-w]

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

*Example*: install all available signatures::

  $ ./utils/community.py --signatures --force

.. _`Cuckoo Community Repository`: https://github.com/cuckoobox/community
