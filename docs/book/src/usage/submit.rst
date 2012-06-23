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

    usage: submit.py [-h] [--package PACKAGE] [--timeout TIMEOUT]
                     [--options OPTIONS] [--priority PRIORITY] [--machine MACHINE]
                     [--platform PLATFORM]
                     path

    positional arguments:
      path                 Path to the file to analyze

    optional arguments:
      -h, --help           show this help message and exit
      --package PACKAGE    Specify an analysis package
      --timeout TIMEOUT    Specify an analysis timeout
      --options OPTIONS    Specify options for the analysis package (e.g.
                           "name=value,name2=value2")
      --priority PRIORITY  Specify a priority for the analysis represented by an
                           integer
      --machine MACHINE    Specify the identifier of a machine you want to use
      --platform PLATFORM  Specify the operating system platform you want to use
                           (windows/darwin/linux)

The concept of analysis packages will be dealt later in this documentation (at
:doc:`packages`). Following are some usage examples:

**Example**: submit a local binary::

    $ ./submit.py /path/to/binary

**Example**: submit a local binary and specify an higher priority::

    $ ./submit.py --priority 5 /path/to/binary

**Example**: submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ ./submit.py --timeout 60 /path/to/binary

**Example**: submit a local binary and specify a custom analysis package::

    $ ./submit.py --package <name of package> /path/to/binary

**Example**: submit a local binary and specify a custom analysis package and 
some options (in this case a command line argument for the malware)::

    $ ./submit.py --package exe --options arguments=--dosomething /path/to/binary.exe

**Example**: submit a local binary to be run on virtual machine *cuckoo1*::

    $ ./submit.py --machine cuckoo1 /path/to/binary

**Example**: submit a local binary to be run on a Windows machine::

    $ ./submit.py --platform windows /path/to/binary

Interact with SQLite
====================

Cuckoo is designed to be easily integrated in larger solutions and to be fully
automated. In order to automate analysis submission or to provide a different
interface rather than the command-line (for instance a web interface), you can
directly interact with the SQLite database located at *db/cuckoo.db*.

The database contains the table *queue* which is defined as the following schema:

    .. code-block:: sql
        :linenos:

        CREATE TABLE tasks (
            id INTEGER PRIMARY KEY,
            md5 TEXT DEFAULT NULL,
            file_path TEXT NOT NULL,
            timeout INTEGER DEFAULT NULL,
            priority INTEGER DEFAULT 0,
            custom TEXT DEFAULT NULL,
            machine TEXT DEFAULT NULL,
            package TEXT DEFAULT NULL,
            options TEXT DEFAULT NULL,
            platform TEXT DEFAULT NULL,
            added_on DATE DEFAULT CURRENT_TIMESTAMP,
            completed_on DATE DEFAULT NULL,
            lock INTEGER DEFAULT 0,
            status INTEGER DEFAULT 0
        );

Following are the details on the fields:

    * ``id``: it's the numeric ID also used to name the results folder of the analysis.
    * ``md5``: it's the MD5 hash of the target file.
    * ``file_path``: it's the path pointing to the file to analyze.
    * ``timeout``: it's the analysis timeout, if none has been specified the field is set to NULL.
    * ``priority``: it's the analysis priority, if none has been specified the field is set to NULL.
    * ``custom``: it's a custom user-defined text that can be used for synchronization between submission and post-analysis processing.
    * ``machine``: it's the ID of a virtual machine the user specifically wants to use for the analysis.
    * ``package``: it's the name of the analysis package to be used, if non has been specified the field is set to NULL.
    * ``options``: it's a comma-separated list of options to pass to the analysis package.
    * ``platform``: it's the operating system platform to use for this analysis.
    * ``added_on``: it's the timestamp of when the analysis request was added.
    * ``completed_on``: it's the timestamp of when the analysis has been completed.
    * ``lock``: it's field internally used by Cuckoo to lock pending analysis.
    * ``status``: it's a numeric field representing the status of the analysis (0 = not completed, 1 = completed successfully, 2 = failed).

Cuckoo Python Functions
=======================

In case you want to write your own Python submission script, you can use the
``add()`` function provided by Cuckoo, which has the following prototype:

    .. code-block:: python

        def add(self,
                file_path,
                md5=None,
                timeout=None,
                package=None,
                options=None,
                priority=None,
                custom=None,
                machine=None,
                platform=None):

Following is a usage example:

    .. code-block:: python
        :linenos:

        #!/usr/bin/env python
        from lib.cuckoo.core.database import Database

        db = Database()
        db.add("/path/to/binary")

