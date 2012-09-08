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

    Running clean.sh will delete:
    * Analyses
    * Binaries
    * Cuckoo task's database
    * Cuckoo logs

To clean your setup, run::

    $ cd utils
    $ sh clean.sh

Submission Utility
==================

Submits sample to analysis. This tool is already described in :doc:`submit`.

Web Utility
===========

Cuckoo's web interface. This tool is already described in :doc:`submit`.

Test Report Utility
===================

Run the reporting engine (run all reports) on an already available analysis
folder, in order to not re-run the analysis if you want to re-generate the
reports for it.
This is used mainly in debugging and developing Cuckoo.
For example if you want run again the report engine for analysis number 1::

    $ cd utils
    $ python testreport.py ../storage/analyses/1/

Test Signature Utility
======================

Run the signature engine (checks all signatures) on an already available 
analysis folder and see possible matches.
This is used mainly in debugging and developing Cuckoo and testing new
signatures.
For example if you want run again the singature engine for analysis number 1::

    $ cd utils
    $ python testsignatures.py ../storage/analyses/1/

Community Download Utility
==========================

This utility downloads signatures from `Cuckoo Community Repository`_ and installs
specific additional modules in your local setup and for example update id with
all the latest available signatures.
Following are the usage options::

    $ cd utils
    $ python community.py
    You need to enable some category!

    usage: community.py [-h] [-a] [-s] [-f] [-w]

    optional arguments:
      -h, --help        show this help message and exit
      -a, --all         Download everything
      -s, --signatures  Download Cuckoo signatures
      -f, --force       Install files without confirmation
      -w, --rewrite     Rewrite existing files

**Example**: install all available signatures::

  $ ./utils/community.py --signatures --force

.. _`Cuckoo Community Repository`: https://github.com/cuckoobox/community
