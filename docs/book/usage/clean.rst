.. _cuckoo-clean:

===========================
Clean all Tasks and Samples
===========================

Since Cuckoo 1.2 a built-in **clean** feature has been added, it
drops all associated information of the tasks and samples in the
database, on the harddisk, and from MongoDB. If you submit a task after
running **clean** you'll start over with ``Task #1`` again.

To clean your setup, run::

    $ cuckoo clean

To sum up, this command does the following:

* Delete analysis results.
* Delete submitted binaries.
* Delete all associated information of the tasks and samples in the configured
  database.
* Delete all data in the configured MongoDB (if configured and enabled in
  ``$CWD/conf/reporting.conf``).

.. warning::
   If you use this command you will delete permanently all data stored by
   Cuckoo in all storages: file system, SQL database and MongoDB database. Use
   it only if you are sure you would clean up all the data.
