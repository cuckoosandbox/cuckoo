==================
Distributed Cuckoo
==================

As mentioned in :doc:`submit`, Cuckoo provides a REST API for Distributed
Cuckoo usage. The standalone distributed script allows one to setup a single
REST API point to which samples and URLs can be submitted which will then, in
turn, be submitted to one of the configured Cuckoo nodes.

A typical setup thus includes a machine on which the distributed script is run
and one or more machines running an instance of the Cuckoo daemon
(``./cuckoo.py``) and the :doc:`Cuckoo REST API <api>`.

A few notes;

* Using the distributed script makes more sense when running at least two
  cuckoo nodes.
* The distributed script can be run on a machine that also runs a Cuckoo
  daemon and REST API, however, make sure it has enough disk space if the
  intention is to submit a lot of samples.

Dependencies
============

The distributed script uses a few Python libraries which can be installed
through the following command (on Debian/Ubuntu)::

    $ sudo pip install flask flask-restful flask-sqlalchemy requests

Starting the Distributed REST API
=================================

The Distributed REST API requires a few commandline options in order to run.
Following is a listing of all available commandline options::

    $ ./utils/dist.py -h

    usage: dist.py [-h] [-d] [--db DB] --samples-directory SAMPLES_DIRECTORY
                [--uptime-logfile UPTIME_LOGFILE] --report-formats
                REPORT_FORMATS --reports-directory REPORTS_DIRECTORY
                [host] [port]

    positional arguments:
        host                  Host to listen on
        port                  Port to listen on

    optional arguments:
        -h, --help            show this help message and exit
        -d, --debug           Enable debug logging
        --db DB               Database connection string
        --samples-directory SAMPLES_DIRECTORY
                                Samples directory
        --uptime-logfile UPTIME_LOGFILE
                                Uptime logfile path
        --report-formats REPORT_FORMATS
                                Reporting formats to fetch
        --reports-directory REPORTS_DIRECTORY
                                Reports directory

In particular the ``--report-formats``, ``--samples-directory``, and
``--reports-directory`` are required.

Report Formats
--------------

The reporting formats denote which reports you'd like to retrieve later on.
Note that all task-related data will be removed from the Cuckoo nodes once the
related reports have been fetches so that the machines are not running out of
disk space. This does, however, force you to specify all the report formats
that you're interested in, because otherwise that information will be lost.

Reporting formats include, but are not limited to and may also include your
own reporting formats, ``json``, ``html``, etc.

Samples Directory
-----------------

The samples directory denotes the directory where the submitted samples will
be stored *temporarily*, until they're passed on to a Cuckoo node and
processed.

Reports Directory
-----------------

Much like the ``Samples Directory`` the Reports Directory defines the
directory where reports will be stored until they're fetched and deleted from
the Distributed REST API.

RESTful resources
=================

Following are all RESTful resources. We first get to the :ref:`quick-usage`
section before going into every resource in detail, though.

+-----------------------------------+---------------------------------------------------------------+
| Resource                          | Description                                                   |
+===================================+===============================================================+
| ``GET`` :ref:`node_root_get`      | Get a list of all enabled Cuckoo nodes.                       |
+-----------------------------------+---------------------------------------------------------------+
| ``POST`` :ref:`node_root_post`    | Register a new Cuckoo node.                                   |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`node_get`           | Get basic information about a node.                           |
+-----------------------------------+---------------------------------------------------------------+
| ``PUT`` :ref:`node_put`           | Update basic information of a node.                           |
+-----------------------------------+---------------------------------------------------------------+
| ``DELETE`` :ref:`node_delete`     | Disable (not completely remove!) a node.                      |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`task_root_get`      | Get a list of all (or a part) of the tasks in the database.   |
+-----------------------------------+---------------------------------------------------------------+
| ``POST`` :ref:`task_root_post`    | Create a new analysis task.                                   |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`task_get`           | Get basic information about a task.                           |
+-----------------------------------+---------------------------------------------------------------+
| ``DELETE`` :ref:`task_delete`     | Delete all associated information of a task.                  |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`report_get`         + Fetch an analysis report.                                     |
+-----------------------------------+---------------------------------------------------------------+

Quick usage
===========

For practical usage the following few commands will be most interesting.

Register a Cuckoo node - a Cuckoo REST API running on the same machine in this
case::

    $ curl http://localhost:9003/node -F name=localhost -F url=http://localhost:8090/

Disable a Cuckoo node::

    $ curl -XDELETE http://localhost:9003/node/<name>

Submit a new analysis task without any special requirements (e.g., using
Cuckoo ``tags``, a particular machine, etc)::

    $ curl http://localhost:9003/task -F file=@/path/to/sample.exe

Get the report of a task has been finished (if it hasn't finished you'll get
a 404 page). Following example will default to the ``JSON`` report::

    $ curl http://localhost:9003/report/1

In order to fetch an XML report such as a MAEC report, use the following
instead::

    $ curl http://localhost:9003/report/1/maec -H 'Accept: application/xml'
