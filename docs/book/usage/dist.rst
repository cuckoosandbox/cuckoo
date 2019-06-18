==================
Distributed Cuckoo
==================

As mentioned in :doc:`submit`, Cuckoo provides a REST API for Distributed
Cuckoo usage. Distributed Cuckoo allows one to setup a single REST API
point to which samples and URLs can be submitted which will then, in turn, be
submitted to one of the configured Cuckoo nodes.

A typical setup thus includes a machine on which Distributed Cuckoo is run
and one or more machines running an instance of the Cuckoo daemon and the
:doc:`Cuckoo REST API <api>`.

A few notes:

* Using Distributed Cuckoo only makes sense when running at least two
  cuckoo nodes.
* Distributed Cuckoo can be run on a machine that also runs a Cuckoo
  daemon and REST API, however, make sure it has enough disk space if the
  intention is to submit a lot of samples.

Starting the Distributed REST API
=================================

The Distributed REST API has the following command line options::

    $ cuckoo distributed server --help
    Usage: cuckoo distributed server [OPTIONS]

    Options:
      -H, --host TEXT     Host to bind the Distributed Cuckoo server on
      -p, --port INTEGER  Port to bind the Distributed Cuckoo server on
      --uwsgi             Dump uWSGI configuration
      --nginx             Dump nginx configuration
      --help              Show this message and exit.

As may be derived from the help output, starting Distributed Cuckoo may be as
simple as running ``cuckoo distributed server``.

The various configuration options are described in the configuration file, but
following we have more in-depth descriptions as well. More advanced usage
naturally includes deployment using ``uWSGI`` and ``nginx``.

Distributed Cuckoo Configuration
================================

Report Formats
--------------

The reporting formats denote which reports you'd like to retrieve later on.
Note that all task-related data will be removed from the Cuckoo nodes once the
related reports have been fetched so that the machines are not running out of
disk space. This does, however, force you to specify all the report formats
that you're interested in, because otherwise that information will be lost.

Reporting formats include, but are not limited to and may also include your
own reporting formats, ``report.json``, ``report.html``, etc.

Samples Directory
-----------------

The samples directory denotes the directory where the submitted samples will
be stored temporarily, until the associated task has been deleted.

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
| ``POST`` :ref:`node_refresh`      | Refresh a Cuckoo nodes metadata.                              |
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
| ``GET`` :ref:`report_get`         | Fetch an analysis report.                                     |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`pcap_get`           | Fetches the PCAP of an analysis.                              |
+-----------------------------------+---------------------------------------------------------------+

.. _node_root_get:

GET /api/node
-------------

Returns all enabled nodes. For each node the information includes the
associated name, its API URL, and machines::

    $ curl http://localhost:9003/api/node
    {
        "success": true,
        "nodes": {
            "localhost": {
                "machines": [
                    {
                        "name": "cuckoo1",
                        "platform": "windows",
                        "tags": []
                    }
                ],
                "name": "localhost",
                "url": "http://localhost:8090/"
            }
        }
    }

.. _node_root_post:

POST /api/node
--------------

Register a new Cuckoo node by providing the name and the URL::

    $ curl http://localhost:9003/api/node -F name=localhost \
        -F url=http://localhost:8090/
    {
        "success": true
    }

.. _node_get:

GET /api/node/<name>
--------------------

Get basic information about a particular Cuckoo node::

    $ curl http://localhost:9003/api/node/localhost
    {
        "success": true,
        "nodes": [
            {
                "name": "localhost",
                "url": "http://localhost:8090/"
                "machines": [
                    {
                        "name": "cuckoo1",
                        "platform": "windows",
                        "tags": []
                    }
                ]
            }
        ]
    }

.. _node_put:

PUT /api/node/<name>
--------------------

Update basic information of a Cuckoo node::

    $ curl -XPUT http://localhost:9003/api/node/localhost -F name=newhost \
        -F url=http://1.2.3.4:8090/
    {
        "success": true
    }

.. _node_refresh:

POST /api/node/<name>/refresh
-----------------------------

Refreshes metadata associated by a Cuckoo node, in particular, its machines::

    $ curl -XPOST http://localhost:9003/api/node/localhost/refresh
    {
        "success": true,
        "machines": [
            {
                "name": "cuckoo1",
                "platform": "windows",
                "tags": []
            },
            {
                "name": "cuckoo2",
                "platform": "windows",
                "tags": []
            }
        ]
    }

.. _node_delete:

DELETE /api/node/<name>
-----------------------

Disable a Cuckoo node, therefore not having it process any new tasks, but
keeping its history in the Distributed Cuckoo database::

    $ curl -XDELETE http://localhost:9003/api/node/localhost
    {
        "success": true
    }

.. _task_root_get:

GET /api/task
-------------

Get a list of all tasks in the database. In order to limit the amount of
results, there's an ``offset``, ``limit``, ``finished``, and ``owner`` field
available::

    $ curl http://localhost:9003/api/task?limit=1
    {
        "success": true,
        "tasks": {
            "1": {
                "clock": null,
                "custom": null,
                "owner": "",
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

POST /api/task
--------------

Submit a new file or URL to be analyzed::

    $ curl http://localhost:9003/api/task -F file=@sample.exe
    {
        "success": true,
        "task_id": 2
    }

.. _task_get:

GET /api/task/<id>
------------------

Get basic information about a particular task::

    $ curl http://localhost:9003/api/task/2
    {
        "success": true,
        "tasks": {
            "2": {
                "id": 2,
                "clock": null,
                "custom": null,
                "owner": "",
                "enforce_timeout": null,
                "machine": null,
                "memory": null,
                "options": null,
                "package": null,
                "path": "/tmp/tmpPwUeXm",
                "platform": "windows",
                "priority": 1,
                "tags": null,
                "timeout": null,
                "task_id": 1,
                "node_id": 2,
                "finished": false
            }
        }
    }

.. _task_delete:

DELETE /api/task/<id>
---------------------

Delete all associated data of a task, namely the binary, the PCAP, and the
reports::

    $ curl -XDELETE http://localhost:9003/api/task/2
    {
        "success": true
    }

.. _report_get:

GET /api/report/<id>/<format>
-----------------------------

Fetch a report for the given task in the specified format::

    # Defaults to the JSON report.
    $ curl http://localhost:9003/api/report/2
    ...

.. _pcap_get:

GET /api/pcap/<id>
------------------

Fetches the PCAP for the given task::

   $ curl http://localhost:9003/api/pcap/2
   ...

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
MySQL. SQLite3 doesn't support multi-threaded applications and as such is not
a good choice for systems such as Cuckoo (as-is).

You should create a database specifically for the distributed cuckoo setup. Do
not be tempted to use any existing cuckoo database in order to avoid update
problems with the DB scripts. In the configuration use the new database name.
The remaining configuration such as usernames, servers, etc can be the same as
for your cuckoo install. Don't forget to use one DB per node and one for the
machine running Distributed Cuckoo (the "management machine" or "controller").

conf/processing.conf
^^^^^^^^^^^^^^^^^^^^

You may want to disable some processing modules, such as ``virustotal``.

conf/reporting.conf
^^^^^^^^^^^^^^^^^^^

Depending on which report(s) are required for integration with your system it
might make sense to only make those report(s) that you're going to use. Thus
disabling the other ones.

conf/virtualbox.conf
^^^^^^^^^^^^^^^^^^^^

Assuming ``VirtualBox`` is the Virtual Machine manager of choice, the ``mode``
will have to be changed to ``headless`` or you will have some restless nights
(this is the default nowadays).

Setup Cuckoo
------------

On each machine you will have to run the Cuckoo Daemon, the Cuckoo API, and
one or more Cuckoo Process instances. For more information on setting that up,
please refer to :doc:`Starting Cuckoo <start>`.

Setup Distributed Cuckoo
------------------------

On the Distributed Cuckoo machine you'll have to setup the Distributed Cuckoo
REST API and the Distributed Cuckoo Worker.

As stated earlier, Distributed Cuckoo REST API may be started by running
``cuckoo distributed server`` or by deploying it properly with ``uWSGI`` and
``nginx``.

The Distributed Cuckoo Worker may be started by running ``supervisorctl start
distributed`` in the ``CWD`` (make sure to start ``supervisord`` first as per
:ref:`cuckoo_background`). This will automatically start the Worker with the
correct configuration and arguments, etc.

Register Cuckoo nodes
---------------------

As outlined in :ref:`quick-usage` the Cuckoo nodes have to be registered with
the Distributed Cuckoo REST API::

    $ curl http://localhost:9003/api/node -F name=cuckoo0 -F url=http://localhost:8090/
    $ curl http://localhost:9003/api/node -F name=cuckoo1 -F url=http://1.2.3.4:8090/

Having registered the Cuckoo nodes all that's left to do now is to submit
tasks and fetch reports once finished. Documentation on these commands can be
found in the :ref:`quick-usage` section. In case your Cuckoo node is not on
``localhost``, replace ``localhost`` with the IP address of the node where
the Cuckoo REST API is running.

If you want to experiment with load balancing between the nodes you may want
to try using a lower value for the ``threshold`` parameter in the
``$CWD/distributed/settings.py`` file as the default value is ``500`` (meaning
tasks are assigned to Cuckoo nodes in batches of 500).

.. _quick-usage:

Quick usage
===========

For practical usage the following few commands will be most interesting.

Register a Cuckoo node, in this case a Cuckoo API running on the same machine
in this case::

    $ curl http://localhost:9003/api/node -F name=localhost -F ip=127.0.0.1

Disable a Cuckoo node::

    $ curl -XDELETE http://localhost:9003/api/node/localhost

Submit a new analysis task without any special requirements (e.g., using
Cuckoo ``tags``, a particular machine, etc)::

    $ curl http://localhost:9003/api/task -F file=@/path/to/sample.exe

Get the report of a task has been finished (if it hasn't finished you'll get
an error with code 420). Following example will default to the ``JSON``
report::

    $ curl http://localhost:9003/api/report/1

If a Cuckoo node gets stuck and needs a reset, the following steps could be
performed to restart it cleanly. Note that this requires usage of our
SaltStack configuration and some manual SQL commands (and preferably the
Distributed Cuckoo Worker is temporary disabled, i.e.,
``supervisorctl stop distributed``)::

    $ psql -c "UPDATE task SET status = 'pending' WHERE status = 'processing' AND node_id = 123"
    $ salt cuckoo1 state.apply cuckoo.clean
    $ salt cuckoo1 state.apply cuckoo.start

If the entire Cuckoo cluster was somehow locked up, i.e., all tasks have been
'assigned', are 'processing', or have the 'finished' status while none of the
Cuckoo nodes are currently working on said analyses (e.g., due to numerous
resets etc), then the following steps may be used to reset the entire state::

    $ supervisorctl -c ~/.cuckoo/supervisord.conf stop distributed
    $ salt '*' state.apply cuckoo.stop
    $ salt '*' state.apply cuckoo.clean
    $ psql -c "UPDATE task SET status = 'pending', node_id = null WHERE status IN ('assigned', 'processing', 'finished')"
    $ salt '*' state.apply cuckoo.start
    $ supervisorctl -c ~/.cuckoo/supervisord.conf start distributed

If a Cuckoo node has a number of tasks that failed to process, therefore
locking up the Cuckoo node altogether, then upgrading the Cuckoo instances
with a bugfixed version and re-processing all analyses may do the trick::

    $ salt cuckoo1 state.apply cuckoo.update  # Upgrade Cuckoo.
    # To make sure there are failed analyses in the first place.
    $ salt cuckoo1 cmd.run "sudo -u cuckoo psql -c \"SELECT * FROM tasks WHERE status = 'failed_processing'\"
    # Reset each analyses to be re-processed.
    $ salt cuckoo1 cmd.run "sudo -u cuckoo psql -c \"UPDATE tasks SET status = 'completed', processing = null WHERE status = 'failed_processing'\""

In order to upgrade the Distributed Cuckoo master, one may want to perform the
following steps::

    $ /etc/init.d/uwsgi stop
    $ supervisorctl -c ~/.cuckoo/supervisord.conf stop distributed
    $ pip uninstall -y cuckoo
    $ pip install cuckoo==2.0.0         # Specify your version here.
    $ pip install Cuckoo-2.0.0.tar.gz   # Or use a locally archived build.
    $ cuckoo distributed migrate
    $ supervisorctl -c ~/.cuckoo/supervisord.conf start distributed
    $ /etc/init.d/uwsgi start
    $ /etc/init.d/nginx restart

In order to test your entire Cuckoo cluster, i.e., every machine on every
Cuckoo node, one may take the ``stuff/distributed/cluster-test.py`` script as
an example. As-is it allows one to check for an active internet connection in
each and every configured machine in the cluster. This script may be used to
identify machines that are incorrect or have been corrupted in one way or
another. Example usage may look as follows::

    # Assuming Distributed Cuckoo listens on localhost and that you want to
    # run the 'internet' script (see also the source of cluster-test.py).
    $ python stuff/distributed/cluster-test.py localhost -s internet
