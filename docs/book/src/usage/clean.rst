.. _cuckoo-clean:

===========================
Clean all Tasks and Samples
===========================

Since Cuckoo 1.2 a built-in **--clean** feature has been added, it
drops all associated information of the tasks and samples in the
database. If you submit a task after running
**--clean** then you'll start with ``Task #1`` again.

To clean your setup, run::

    $ ./cuckoo.py --clean

To sum up, this command does the following:

* Delete analysis results.
* Delete submitted binaries.
* Delete all associated information of the tasks and samples in the configured database.
* Delete all data in the configured MongoDB (if configured and enabled in reporting.conf).

.. warning::
   If you use this command you will delete permanently all data stored by Cuckoo in all
   storages: file system, SQL database and MongoDB database. Use it only if you are sure
   you would clean up all the data.
