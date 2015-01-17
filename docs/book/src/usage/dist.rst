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

Following are all RESTful resources. Also make sure to check out the
:ref:`quick-usage` section which documents the most commonly used commands.

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

.. _node_root_get:

GET /node
---------

Returns all enabled nodes. For each node its associated name, API url, and
machines are returned::

    $ curl http://localhost:9003/node
    {
        "nodes": {
            "localhost": {
                "machines": [
                    {
                        "name": "cuckoo1",
                        "platform": "windows",
                        "tags": [
                            ""
                        ]
                    }
                ],
                "name": "localhost",
                "url": "http://0:8090/"
            }
        }
    }

.. _node_root_post:

POST /node
----------

Register a new Cuckoo node by providing the name and the URL::

    $ curl http://localhost:9003/node -F name=localhost \
        -F url=http://localhost:8090/
    {
        "machines": [
            {
                "name": "cuckoo1",
                "platform": "windows",
                "tags": []
            }
        ],
        "name": "localhost"
    }

.. _node_get:

GET /node/<name>
----------------

Get basic information about a particular Cuckoo node::

    $ curl http://localhost:9003/node/localhost
    {
        "name": "localhost",
        "url": "http://localhost:8090/"
    }

.. _node_put:

PUT /node/<name>
----------------

Update basic information of a Cuckoo node::

    $ curl -XPUT http://localhost:9003/node/localhost -F name=newhost \
        -F url=http://1.2.3.4:8090/
    null

.. _node_delete:

DELETE /node/<name>
-------------------

Disable a Cuckoo node, therefore not having it process any new tasks, but
keep its history in the Distributed's database::

    $ curl -XDELETE http://localhost:9003/node/localhost
    null

.. _task_root_get:

GET /task
---------

Get a list of all tasks in the database (an offset and limit parameter have
yet to be added)::

    $ curl http://localhost:9003/task
    {
        "tasks": {
            "1": {
                "clock": null,
                "custom": null,
                "enforce_timeout": null,
                "machine": null,
                "memory": null,
                "options": null,
                "package": null,
                "path": "/tmp/dist-samples/tmphal8mS",
                "platform": "windows",
                "priority": 1,
                "tags": null,
                "task_id": 1,
                "timeout": null
            }
        }
    }

.. _task_root_post:

POST /task
----------

Submit a new file or URL to be analyzed::

    $ curl http://localhost:9003/task -F file=@sample.exe
    {
        "task_id": 2
    }

.. _task_get:

GET /task/<id>
--------------

Get basic information about a particular task::

    $ curl http://localhost:9003/task/2
    {
        "tasks": {
            "2": {
                "clock": null,
                "custom": null,
                "enforce_timeout": null,
                "machine": null,
                "memory": null,
                "options": null,
                "package": null,
                "path": "/tmp/tmpPwUeXm",
                "platform": "windows",
                "priority": 1,
                "tags": null,
                "task_id": 2,
                "timeout": null
            }
        }
    }

.. _task_delete:

DELETE /task/<id>
-----------------

Delete all associated data of a task, namely the binary and the reports::

    $ curl -XDELETE http://localhost:9003/task/2
    null

.. _report_get:

GET /report/<id>/<format>
-------------------------

Fetch a report for the given task in the specified format::

    # Defaults to the JSON report.
    $ curl http://localhost:9003/report/2
    ...

    # Get an XML report.
    $ curl http://localhost:9003/report/2/maec -H "Accept: application/xml"

.. _quick-usage:

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

Proposed setup
==============

The following description depicts a Distributed Cuckoo setup with two Cuckoo
machines, **cuckoo0** and **cuckoo1**. In this setup the first machine,
cuckoo0, also hosts the Distributed Cuckoo REST API.

Configuration settings
----------------------

Our setup will require a couple of updates with regards to the configuration
files.

conf/cuckoo.conf
^^^^^^^^^^^^^^^^

Update ``process_results`` to ``off`` as we will be running our own results
processing script (for performance reasons).

Update ``tmppath`` to something that holds enough storage to store a few
hundred binaries. On some servers or setups ``/tmp`` may have a limited amount
of space and thus this wouldn't suffice.

Update ``connection`` to use something *not* sqlite3. Preferably PostgreSQL or
MySQL. SQLite3 doesn't support multi-threaded applications that well and this
will give errors at random if used.

conf/processing.conf
^^^^^^^^^^^^^^^^^^^^

You may want to disable some processing modules, such as ``virustotal``.

conf/reporting.conf
^^^^^^^^^^^^^^^^^^^

Depending on which report(s) are required for integration with your system it
might make sense to only make those report(s) that you're going to use. Thus
disable the other ones.

conf/virtualbox.conf
^^^^^^^^^^^^^^^^^^^^

Assuming ``VirtualBox`` is the Virtual Machine manager of choice, the ``mode``
will have to be changed to ``headless`` or you will have some restless nights.

Setup Cuckoo
------------

On each machine the following three scripts should be ran::

    ./cuckoo.py
    ./utils/api.py -H 1.2.3.4  # IP accessible by the Distributed script.
    ./utils/process.py auto

One way to do this is by placing each script in its own ``screen(1)`` session
as follows, this allows one to check back on each script to ensure it's
(still) running successfully::

    $ screen -S cuckoo  ./cuckoo.py
    $ screen -S api     ./utils/api.py
    $ screen -S process ./utils/process.py auto

Setup Distributed Cuckoo
------------------------

On the first machine start a separate ``screen(1)`` session for the
Distributed Cuckoo script with all the required parameters (see the rest of
the documentation on the parameters for this script)::

    $ screen -S distributed ./utils/dist.py --samples-directory /a/b/samples \
        --report-formats json --reports-directory /a/b/reports

Register Cuckoo nodes
---------------------

As outlined in :ref:`quick-usage` the Cuckoo nodes have to be registered with
the Distributed Cuckoo script::

    $ curl http://localhost:9003/node -F name=cuckoo0 -F url=http://localhost:8090/
    $ curl http://1.2.3.4:9003/node -F name=cuckoo1 -F url=http://1.2.3.4:8090/

Having registered the Cuckoo nodes all that's left to do now is to submit
tasks and fetch reports once finished. Documentation on these commands can be
found in the :ref:`quick-usage` section.
