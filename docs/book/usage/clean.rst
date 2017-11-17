.. _cuckoo-clean:

===========================
Clean all Tasks and Samples
===========================

.. versionchanged:: 2.0.0
   Turned into a proper Cuckoo App rather than a standalone script.

Since Cuckoo 1.2 a built-in **clean** feature has been featured, it drops all
associated information of the tasks and samples in the database, on the
harddisk, from MongoDB, and from ElasticSearch. If you submit a task after
running **clean** you'll start over with ``Task #1`` again.

To clean your setup, run::

    $ cuckoo clean

To sum up, this command does the following:

* Delete analysis results.
* Delete submitted binaries.
* Delete all associated information of the tasks and samples in the configured
  database.
* Delete all data in the configured MongoDB database (if configured and
  enabled in ``$CWD/conf/reporting.conf``).
* Delete all data in the configured ElasticSearch database (if configured and
  enabled in ``$CWD/conf/reporting.conf``).

.. warning::
   If you use this command you will permanently delete all data stored by
   Cuckoo in all available storages: the file system, the SQL database, the
   MongoDB database, and the ElasticSearch database. Use it only if you are
   sure you would clean up all the data.
