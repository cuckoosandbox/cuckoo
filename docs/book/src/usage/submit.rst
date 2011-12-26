==================
Submit an analysis
==================

In order to submit a file to be analyzed you can:

    * Use provided **submit.py** utility.
    * Directly interact with the **SQLite database**.
    * Use Cuckoo **Python functions** directly from Cuckoo's library.

Submission Utility
==================

The easiest way to submit an analysis is to use the provided *submit.py*
command-line utility. It currently has the following options available::

    Usage: submit.py [options] filepath

    Options:
      -h, --help            show this help message and exit
      -t TIMEOUT, --timeout=TIMEOUT
                            Specify analysis execution time limit
      -p PACKAGE, --package=PACKAGE
                            Specify custom analysis package name
      -r PRIORITY, --priority=PRIORITY
                            Specify an analysis priority expressed in integer
      -c CUSTOM, --custom=CUSTOM
                            Specify any custom value to be passed to postprocessing
      -d, --download        Specify if the target is an URL to be downloaded
      -u, --url             Specify if the target is an URL to be analyzed
      -m MACHINE, --machine=MACHINE
                            Specify a virtual machine you want to specifically use for this analysis


The concept of analysis packages will be dealt later in this documentation (at
:doc:`packages`). Following are some usage examples:

**Example**: submit a local binary::

    $ python submit.py /path/to/binary

**Example**: submit a local binary and specify an higher priority::

    $ python submit.py /path/to/binary --priority 5

**Example**: submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ python submit.py /path/to/binary --timeout 60

**Example**: submit a local binary and specify a custom analysis package::

    $ python submit.py /path/to/binary --package <name of package>

**Example**: submit an URL to be downloaded locally and analyzed::

    $ python submit.py --download http://www.website.tld/file.exe

**Example**: submit an URL to be analyzed within Internet Explorer::

    $ python submit.py --url http://maliciousurl.tld/exploit.php

**Example**: submit a local binary to be run on virtual machine *cuckoo1*::

    $ python submit.py /path/to/binary --machine cuckoo1

Interact with SQLite
====================

Cuckoo is designed to be easily integrated in larger solutions and to be fully
automated. In order to automate analysis submission or to provide a different
interface rather than the command-line (for instance a web interface), you can
directly interact with the SQLite database located at *db/cuckoo.db*.

The database contains the table *queue* which is defined as the following schema:

    .. code-block:: sql
        :linenos:

        CREATE TABLE queue (
          id INTEGER PRIMARY KEY,
          md5 TEXT DEFAULT NULL,
          target TEXT NOT NULL,
          timeout INTEGER DEFAULT NULL,
          priority INTEGER DEFAULT 0,
          added_on DATE DEFAULT CURRENT_TIMESTAMP,
          completed_on DATE DEFAULT NULL,
          package TEXT DEFAULT NULL,
          lock INTEGER DEFAULT 0,
          status INTEGER DEFAULT 0,
          custom TEXT DEFAULT NULL,
          vm_id TEXT DEFAULT NULL
        );

Following are the details on the fields:

    * ``id``: it's the numeric ID also used to name the results folder of the analysis.
    * ``md5``: it's the MD5 hash of the target file.
    * ``target``: it's the path pointing to the file to analyze.
    * ``timeout``: it's the analysis timeout, if none has been specified the field is set to NULL.
    * ``priority``: it's the analysis priority, if none has been specified the field is set to NULL.
    * ``added_on``: it's the timestamp of when the analysis request was added.
    * ``completed_on``: it's the timestamp of when the analysis has been completed.
    * ``package``: it's the name of the analysis package to be used, if non has been specified the field is set to NULL.
    * ``lock``: it's field internally used by Cuckoo to lock pending analysis.
    * ``status``: it's a numeric field representing the status of the analysis (0 = not completed, 1 = completed successfully, 2 = failed).
    * ``custom``: it's a custom user-defined text that can be used for synchronization between submission and post-analysis processing.
    * ``vm_id``: it's the ID (as defined in cuckoo.conf) of a virtual machine the user specifically wants to use for the analysis.

Cuckoo Python Functions
=======================

In case you want to write your own Python submission script, you can use the
``add_task()`` function provided by Cuckoo, which has the following prototype:

    .. code-block:: python

        def add_task(self, target, md5 = None, timeout = None, package = None, priority = None, custom = None, vm_id = None)

Following is a usage example:

    .. code-block:: python
        :linenos:

        #!/usr/bin/python
        from cuckoo.core.db import CuckooDatabase

        db = CuckooDatabase()
        db.add_task("/path/to/binary")

