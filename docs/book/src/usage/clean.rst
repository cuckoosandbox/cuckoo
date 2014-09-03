.. _cuckoo-clean:

===========================
Clean all Tasks and Samples
===========================

Since Cuckoo 1.2 a built-in **--clean** feature has been added which does not
only have the same functionality as the now-deprecated :ref:`./utils/clean.sh
utility <cleanup-utility>`, but also drops all associated information of the
tasks and samples in the database. If you submit a task after running
**--clean** then you'll start with ``Task #1`` again.

To clean your setup, run::

    $ ./cuckoo.py --clean

To sum up, this command does the following.

* Delete analysis results.
* Delete submitted binaries.
* Delete all associated information of the tasks and samples in the database.

If you are using the MongoDB reporting module clean.sh does **not** clean your
database, you have to take care of that.
