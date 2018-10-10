========
REST API
========

As mentioned in :doc:`submit`, Cuckoo provides a simple and lightweight REST
API server that is under the hood implemented using `Flask`_.

.. _`Flask`: http://flask.pocoo.org/

Starting the API server
=======================

In order to start the API server you can simply do::

    $ cuckoo api

By default it will bind the service on **localhost:8090**. If you want to change
those values, you can use the following syntax::

    $ cuckoo api --host 0.0.0.0 --port 1337
    $ cuckoo api -H 0.0.0.0 -p 1337

To allow only authenticated access to the API, the ``api_token`` in
``cuckoo.conf`` must be set to a secret value. In new Cuckoo installations,
a random token is automatically generated for you.
To access the API, you must send the ``Authorization: Bearer <token>`` header
with all your requests using the token defined in the configuration.
Note that if you want to access the API over an insecure network such as the
Internet, you should run the API server behind `nginx`_ described in the
next section and enable HTTPS.

Web deployment
--------------

While the default method of starting the API server works fine for many cases,
some users may wish to deploy the server in a robust manner. This can be done
by exposing the API as a WSGI application through a web server. This section shows
a simple example of deploying the API via `uWSGI`_ and `nginx`_. These
instructions are written with Ubuntu GNU/Linux in mind, but may be adapted for
other platforms.

This solution requires uWSGI, the uWSGI Python plugin, and nginx. All are
available as packages::

    $ sudo apt-get install uwsgi uwsgi-plugin-python nginx

uWSGI setup
^^^^^^^^^^^

First, use uWSGI to run the API server as an application.

To begin, create a uWSGI configuration file at
``/etc/uwsgi/apps-available/cuckoo-api.ini`` that contains the actual
configuration as reported by the ``cuckoo api --uwsgi`` command::

    $ cuckoo api --uwsgi
    [uwsgi]
    plugins = python
    virtualenv = /home/cuckoo/cuckoo
    module = cuckoo.apps.api
    callable = app
    uid = cuckoo
    gid = cuckoo
    env = CUCKOO_APP=api
    env = CUCKOO_CWD=/home/..somepath..

This configuration inherits a number of settings from the distribution's
default uWSGI configuration and imports ``cuckoo.apps.api`` from the Cuckoo
package to do the actual work. In this example we installed Cuckoo in a
virtualenv located at ``/home/cuckoo/cuckoo``. If Cuckoo is installed globally
no virtualenv option is required.

Enable the app configuration and start the server.

.. code-block:: bash

    $ sudo ln -s /etc/uwsgi/apps-available/cuckoo-api.ini /etc/uwsgi/apps-enabled/
    $ sudo service uwsgi start cuckoo-api    # or reload, if already running

.. note::

   Logs for the application may be found in the standard directory for distribution
   app instances, i.e., ``/var/log/uwsgi/app/cuckoo-api.log``.
   The UNIX socket is created in a conventional location as well,
   ``/run/uwsgi/app/cuckoo-api/socket``.

nginx setup
^^^^^^^^^^^

With the API server running in uWSGI, nginx can now be set up to run as a web
server/reverse proxy, backending HTTP requests to it.

To begin, create a nginx configuration file at
``/etc/nginx/sites-available/cuckoo-api`` that contains the actual
configuration as reportd by the ``cuckoo api --nginx`` command::

    $ cuckoo api --nginx
    upstream _uwsgi_cuckoo_api {
        server unix:/run/uwsgi/app/cuckoo-api/socket;
    }

    server {
        listen localhost:8090;

        # REST API app
        location / {
            client_max_body_size 1G;
            uwsgi_pass  _uwsgi_cuckoo_api;
            include     uwsgi_params;
        }
    }

Make sure that nginx can connect to the uWSGI socket by placing its user in the
**cuckoo** group::

    $ sudo adduser www-data cuckoo

Enable the server configuration and start the server.

.. code-block:: bash

    $ sudo ln -s /etc/nginx/sites-available/cuckoo-api /etc/nginx/sites-enabled/
    $ sudo service nginx start    # or reload, if already running

At this point, the API server should be available at port **8090** on the server.
Various configurations may be applied to extend this configuration, such as to
tune server performance, add authentication, or to secure communications using
HTTPS.

.. _`uWSGI`: http://uwsgi-docs.readthedocs.org/en/latest/
.. _`nginx`: http://nginx.org/

Resources
=========

Following is a list of currently available resources and a brief description of
each one. For details click on the resource name.

+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Resource                            | Description                                                                                                      |
+=====================================+==================================================================================================================+
| ``POST`` :ref:`tasks_create_file`   | Adds a file to the list of pending tasks to be processed and analyzed.                                           |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``POST`` :ref:`tasks_create_url`    | Adds an URL to the list of pending tasks to be processed and analyzed.                                           |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``POST`` :ref:`tasks_create_submit` | Adds one or more files and/or files embedded in archives to the list of pending tasks.                           |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_list`           | Returns the list of tasks stored in the internal Cuckoo database.                                                |
|                                     | You can optionally specify a limit of entries to return.                                                         |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_sample`         | Returns the list of tasks stored in the internal Cuckoo database for a given sample.                             |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_view`           | Returns the details on the task assigned to the specified ID.                                                    |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_reschedule`     | Reschedule a task assigned to the specified ID.                                                                  |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_delete`         | Removes the given task from the database and deletes the results.                                                |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_report`         | Returns the report generated out of the analysis of the task associated with the specified ID.                   |
|                                     | You can optionally specify which report format to return, if none is specified the JSON report will be returned. |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_shots`          | Retrieves one or all screenshots associated with a given analysis task ID.                                       |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_rereport`       | Re-run reporting for task associated with a given analysis task ID.                                              |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_reboot`         | Reboot a given analysis task ID.                                                                                 |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`memory_list`          | Returns a list of memory dump files associated with a given analysis task ID.                                    |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`memory_get`           | Retrieves one memory dump file associated with a given analysis task ID.                                         |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`files_view`           | Search the analyzed binaries by MD5 hash, SHA256 hash or internal ID (referenced by the tasks details).          |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`files_get`            | Returns the content of the binary with the specified SHA256 hash.                                                |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`pcap_get`             | Returns the content of the PCAP associated with the given task.                                                  |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`machines_list`        | Returns the list of analysis machines available to Cuckoo.                                                       |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`machines_view`        | Returns details on the analysis machine associated with the specified name.                                      |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`cuckoo_status`        | Returns the basic cuckoo status, including version and tasks overview.                                           |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`vpn_status`           | Returns VPN status.                                                                                              |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`exit`                 | Shuts down the API server.                                                                                       |
+-------------------------------------+------------------------------------------------------------------------------------------------------------------+

.. _tasks_create_file:

/tasks/create/file
------------------

**POST /tasks/create/file**

Adds a file to the list of pending tasks. Returns the ID of the newly created task.

**Example request**::

    curl -H "Authorization: Bearer S4MPL3" -F file=@/path/to/file http://localhost:8090/tasks/create/file

**Example request using Python**..

.. code-block:: python

    import requests

    REST_URL = "http://localhost:8090/tasks/create/file"
    SAMPLE_FILE = "/path/to/malwr.exe"
    HEADERS = {"Authorization": "Bearer S4MPL3"}

    with open(SAMPLE_FILE, "rb") as sample:
        files = {"file": ("temp_file_name", sample)}
        r = requests.post(REST_URL, headers=HEADERS, files=files)

    # Add your code to error checking for r.status_code.

    task_id = r.json()["task_id"]

    # Add your code for error checking if task_id is None.

**Example response**.

.. code-block:: json

    {
        "task_id" : 1
    }

**Form parameters**:

* ``file`` *(required)* - sample file (multipart encoded file content)
* ``package`` *(optional)* - analysis package to be used for the analysis
* ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
* ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
* ``options`` *(optional)* - options to pass to the analysis package
* ``machine`` *(optional)* - label of the analysis machine to use for the analysis
* ``platform`` *(optional)* - name of the platform to select the analysis machine from (e.g. "windows")
* ``tags`` *(optional)* - define machine to start by tags. Platform must be set to use that. Tags are comma separated
* ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
* ``owner`` *(optional)* - task owner in case multiple users can submit files to the same cuckoo instance
* ``clock`` *(optional)* - set virtual machine clock (format %m-%d-%Y %H:%M:%S)
* ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
* ``unique`` *(optional)* - only submit samples that have not been analyzed before
* ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value

**Status codes**:

* ``200`` - no error
* ``400`` - duplicated file detected (when using unique option)

.. _tasks_create_url:

/tasks/create/url
-----------------

**POST /tasks/create/url**

Adds a file to the list of pending tasks. Returns the ID of the newly created task.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" -F url="http://www.malicious.site" http://localhost:8090/tasks/create/url

**Example request using Python**.

.. code-block:: python

    import requests

    REST_URL = "http://localhost:8090/tasks/create/url"
    SAMPLE_URL = "http://example.org/malwr.exe"
    HEADERS = {"Authorization": "Bearer S4MPL3"}

    data = {"url": SAMPLE_URL}
    r = requests.post(REST_URL, headers=HEADERS, data=data)

    # Add your code to error checking for r.status_code.

    task_id = r.json()["task_id"]

    # Add your code to error checking if task_id is None.

**Example response**.

.. code-block:: json

    {
        "task_id" : 1
    }

**Form parameters**:

* ``url`` *(required)* - URL to analyze (multipart encoded content)
* ``package`` *(optional)* - analysis package to be used for the analysis
* ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
* ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
* ``options`` *(optional)* - options to pass to the analysis package
* ``machine`` *(optional)* - label of the analysis machine to use for the analysis
* ``platform`` *(optional)* - name of the platform to select the analysis machine from (e.g. "windows")
* ``tags`` *(optional)* - define machine to start by tags. Platform must be set to use that. Tags are comma separated
* ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
* ``owner`` *(optional)* - task owner in case multiple users can submit files to the same cuckoo instance
* ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
* ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
* ``clock`` *(optional)* - set virtual machine clock (format %m-%d-%Y %H:%M:%S)

**Status codes**:

* ``200`` - no error

.. _tasks_create_submit:

/tasks/create/submit
--------------------

**POST /tasks/create/submit**

Adds one or more files and/or files embedded in archives *or* a newline
separated list of URLs/hashes to the list of pending tasks. Returns the
submit ID as well as the task IDs of the newly created task(s).

**Example request**.

.. code-block:: bash

    # Submit two executables.
    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/create/submit -F files=@1.exe -F files=@2.exe

    # Submit http://google.com
    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/create/submit -F strings=google.com

    # Submit http://google.com & http://facebook.com
    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/create/submit -F strings=$'google.com\nfacebook.com'

**Example request using Python**.

.. code-block:: python

    import requests

    HEADERS = {"Authorization": "Bearer S4MPL3"}

    # Submit one or more files.
    r = requests.post("http://localhost:8090/tasks/create/submit", files=[
        ("files", open("1.exe", "rb")),
        ("files", open("2.exe", "rb")),
    ], headers=HEADERS)

    # Add your code to error checking for r.status_code.

    submit_id = r.json()["submit_id"]
    task_ids = r.json()["task_ids"]
    errors = r.json()["errors"]

    # Add your code to error checking on "errors".

    # Submit one or more URLs or hashes.
    urls = [
        "google.com", "facebook.com", "cuckoosandbox.org",
    ]
    r = requests.post(
        "http://localhost:8090/tasks/create/submit",
        headers=HEADERS,
        data={"strings": "\n".join(urls)}
    )

**Example response** from the executable submission.

.. code-block:: json

    {
        "submit_id": 1,
        "task_ids": [1, 2],
        "errors": []
    }

**Form parameters**:

* ``file`` *(optional)* - backwards compatibility with naming scheme for :ref:`tasks_create_file`
* ``files`` *(optional)* - sample(s) to inspect and add to our pending queue
* ``strings`` *(optional)* - newline separated list of URLs and/or hashes (to be obtained using your VirusTotal API key)
* ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
* ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
* ``options`` *(optional)* - options to pass to the analysis package
* ``tags`` *(optional)* - define machine to start by tags. Platform must be set to use that. Tags are comma separated
* ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
* ``owner`` *(optional)* - task owner in case multiple users can submit files to the same cuckoo instance
* ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
* ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
* ``clock`` *(optional)* - set virtual machine clock (format %m-%d-%Y %H:%M:%S)

**Status codes**:

* ``200`` - no error

.. _tasks_list:

/tasks/list
-----------

**GET /tasks/list/** *(int: limit)* **/** *(int: offset)*

Returns list of tasks.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/list

**Example response**.

.. code-block:: json

    {
        "tasks": [
            {
                "category": "url",
                "machine": null,
                "errors": [],
                "target": "http://www.malicious.site",
                "package": null,
                "sample_id": null,
                "guest": {},
                "custom": null,
                "owner": "",
                "priority": 1,
                "platform": null,
                "options": null,
                "status": "pending",
                "enforce_timeout": false,
                "timeout": 0,
                "memory": false,
                "tags": []
                "id": 1,
                "added_on": "2012-12-19 14:18:25",
                "completed_on": null
            },
            {
                "category": "file",
                "machine": null,
                "errors": [],
                "target": "/tmp/malware.exe",
                "package": null,
                "sample_id": 1,
                "guest": {},
                "custom": null,
                "owner": "",
                "priority": 1,
                "platform": null,
                "options": null,
                "status": "pending",
                "enforce_timeout": false,
                "timeout": 0,
                "memory": false,
                "tags": [
                            "32bit",
                            "acrobat_6",
                        ],
                "id": 2,
                "added_on": "2012-12-19 14:18:25",
                "completed_on": null
            }
        ]
    }

**Parameters**:

* ``limit`` *(optional)* *(int)* - maximum number of returned tasks
* ``offset`` *(optional)* *(int)* - data offset

**Status codes**:

* ``200`` - no error

.. _tasks_sample:

/tasks/sample
-------------

**GET /tasks/sample/** *(int: sample_id)*

Returns list of tasks for sample.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/sample/1

**Example response**.

.. code-block:: json

    {
        "tasks": [
            {
                "category": "file",
                "machine": null,
                "errors": [],
                "target": "/tmp/malware.exe",
                "package": null,
                "sample_id": 1,
                "guest": {},
                "custom": null,
                "owner": "",
                "priority": 1,
                "platform": null,
                "options": null,
                "status": "pending",
                "enforce_timeout": false,
                "timeout": 0,
                "memory": false,
                "tags": [
                            "32bit",
                            "acrobat_6",
                        ],
                "id": 2,
                "added_on": "2012-12-19 14:18:25",
                "completed_on": null
            }
        ]
    }

**Parameters**:

* ``sample_id`` *(required)* *(int)* - sample id to list tasks for

**Status codes**:

* ``200`` - no error

.. _tasks_view:

/tasks/view
-----------

**GET /tasks/view/** *(int: id)*

Returns details on the task associated with the specified ID.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/view/1

**Example response**.

.. code-block:: json

    {
        "task": {
            "category": "url",
            "machine": null,
            "errors": [],
            "target": "http://www.malicious.site",
            "package": null,
            "sample_id": null,
            "guest": {},
            "custom": null,
            "owner": "",
            "priority": 1,
            "platform": null,
            "options": null,
            "status": "pending",
            "enforce_timeout": false,
            "timeout": 0,
            "memory": false,
            "tags": [
                        "32bit",
                        "acrobat_6",
                    ],
            "id": 1,
            "added_on": "2012-12-19 14:18:25",
            "completed_on": null
        }
    }

Note: possible value for key ``status``:

* ``pending``
* ``running``
* ``completed``
* ``reported``

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to lookup

**Status codes**:

* ``200`` - no error
* ``404`` - task not found

.. _tasks_reschedule:

/tasks/reschedule
-----------------

**GET /tasks/reschedule/** *(int: id)* **/** *(int: priority)*

Reschedule a task with the specified ID and priority (default priority
is 1).

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/reschedule/1

**Example response**.

.. code-block:: json

    {
        "status": "OK"
    }

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to reschedule
* ``priority`` *(optional)* *(int)* - Task priority

**Status codes**:

* ``200`` - no error
* ``404`` - task not found

.. _tasks_delete:

/tasks/delete
-------------

**GET /tasks/delete/** *(int: id)*

Removes the given task from the database and deletes the results.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/delete/1

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to delete

**Status codes**:

* ``200`` - no error
* ``404`` - task not found
* ``500`` - unable to delete the task

.. _tasks_report:

/tasks/report
-------------

**GET /tasks/report/** *(int: id)* **/** *(str: format)*

Returns the report associated with the specified task ID.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/report/1

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to get the report for
* ``format`` *(optional)* - format of the report to retrieve [json/html/all/dropped/package_files]. If none is specified the JSON report will be returned. ``all`` returns all the result files as tar.bz2, ``dropped`` the dropped files as tar.bz2, ``package_files`` files uploaded to host by analysis packages.

**Status codes**:

* ``200`` - no error
* ``400`` - invalid report format
* ``404`` - report not found

.. _tasks_shots:

/tasks/screenshots
------------------

**GET /tasks/screenshots/** *(int: id)* **/** *(str: number)*

Returns one or all screenshots associated with the specified task ID.

**Example request**.

.. code-block:: bash

    wget http://localhost:8090/tasks/screenshots/1

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to get the report for
* ``screenshot`` *(optional)* - numerical identifier of a single screenshot (e.g. 0001, 0002)

**Status codes**:

* ``404`` - file or folder not found

.. _tasks_rereport:

/tasks/rereport
---------------

**GET /tasks/rereport/** *(int: id)*

Re-run reporting for task associated with the specified task ID.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/rereport/1

**Example response**.

.. code-block:: json

    {
        "success": true
    }

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to re-run report

**Status codes**:

* ``200`` - no error
* ``404`` - task not found

.. _tasks_reboot:

/tasks/reboot
-------------

**GET /tasks/reboot/** *(int: id)* **

Add a reboot task to database from an existing analysis ID.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/tasks/reboot/1

**Example response**.

.. code-block:: json

    {
        "task_id": 1,
        "reboot_id": 3
    }

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task

**Status codes**:

* ``200`` - success
* ``404`` - error creating reboot task

.. _memory_list:

/memory/list
------------

**GET /memory/list/** *(int: id)*

Returns a list of memory dump files or one memory dump file associated with the specified task ID.

**Example request**.

.. code-block:: bash

    wget http://localhost:8090/memory/list/1

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to get the report for

**Status codes**:

* ``404`` - file or folder not found

.. _memory_get:

/memory/get
-----------

**GET /memory/get/** *(int: id)* **/** *(str: number)*

Returns one memory dump file associated with the specified task ID.

**Example request**.

.. code-block:: bash

    wget http://localhost:8090/memory/get/1/1908

**Parameters**:

* ``id`` *(required)* *(int)* - ID of the task to get the report for
* ``pid`` *(required)* - numerical identifier (pid) of a single memory dump file (e.g. 205, 1908)

**Status codes**:

* ``404`` - file or folder not found

.. _files_view:

/files/view
-----------

**GET /files/view/md5/** *(str: md5)*

**GET /files/view/sha256/** *(str: sha256)*

**GET /files/view/id/** *(int: id)*

Returns details on the file matching either the specified MD5 hash, SHA256 hash or ID.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/files/view/id/1

**Example response**.

.. code-block:: json

    {
        "sample": {
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "file_type": "empty",
            "file_size": 0,
            "crc32": "00000000",
            "ssdeep": "3::",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "id": 1,
            "md5": "d41d8cd98f00b204e9800998ecf8427e"
        }
    }

**Parameters**:

* ``md5`` *(optional)* - MD5 hash of the file to lookup
* ``sha256`` *(optional)* - SHA256 hash of the file to lookup
* ``id`` *(optional)* *(int)* - ID of the file to lookup

**Status codes**:

* ``200`` - no error
* ``400`` - invalid lookup term
* ``404`` - file not found

.. _files_get:

/files/get
----------

**GET /files/get/** *(str: sha256)*

 Returns the binary content of the file matching the specified SHA256 hash.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/files/get/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 > sample.exe

**Status codes**:

* ``200`` - no error
* ``404`` - file not found

.. _pcap_get:

/pcap/get
---------

**GET /pcap/get/** *(int: task)*

Returns the content of the PCAP associated with the given task.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/pcap/get/1 > dump.pcap

**Status codes**:

* ``200`` - no error
* ``404`` - file not found

.. _machines_list:

/machines/list
--------------

**GET /machines/list**

Returns a list with details on the analysis machines available to Cuckoo.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/machines/list

**Example response**.

.. code-block:: json

    {
        "machines": [
            {
                "status": null,
                "locked": false,
                "name": "cuckoo1",
                "resultserver_ip": "192.168.56.1",
                "ip": "192.168.56.101",
                "tags": [
                            "32bit",
                            "acrobat_6",
                        ],
                "label": "cuckoo1",
                "locked_changed_on": null,
                "platform": "windows",
                "snapshot": null,
                "interface": null,
                "status_changed_on": null,
                "id": 1,
                "resultserver_port": "2042"
            }
        ]
    }

**Status codes**:

* ``200`` - no error

.. _machines_view:

/machines/view
--------------

**GET /machines/view/** *(str: name)*

Returns details on the analysis machine associated with the given name.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/machines/view/cuckoo1

**Example response**.

.. code-block:: json

    {
        "machine": {
            "status": null,
            "locked": false,
            "name": "cuckoo1",
            "resultserver_ip": "192.168.56.1",
            "ip": "192.168.56.101",
            "tags": [
                        "32bit",
                        "acrobat_6",
                    ],
            "label": "cuckoo1",
            "locked_changed_on": null,
            "platform": "windows",
            "snapshot": null,
            "interface": null,
            "status_changed_on": null,
            "id": 1,
            "resultserver_port": "2042"
        }
    }

**Status codes**:

* ``200`` - no error
* ``404`` - machine not found

.. _cuckoo_status:

/cuckoo/status
--------------

**GET /cuckoo/status/**

Returns status of the cuckoo server. In version 1.3 the diskspace
entry was added. The diskspace entry shows the used, free, and total
diskspace at the disk where the respective directories can be found.
The diskspace entry allows monitoring of a Cuckoo node through the
Cuckoo API. Note that each directory is checked separately as one
may create a symlink for $CUCKOO/storage/analyses to a separate
harddisk, but keep $CUCKOO/storage/binaries as-is. (This feature is
only available under Unix!)

In version 1.3 the cpuload entry was also added - the cpuload entry
shows the CPU load for the past minute, the past 5 minutes, and the
past 15 minutes, respectively. (This feature is only available under
Unix!)

**Diskspace directories**:

* ``analyses`` - $CUCKOO/storage/analyses/
* ``binaries`` - $CUCKOO/storage/binaries/
* ``temporary`` - ``tmppath`` as specified in ``conf/cuckoo.conf``

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/cuckoo/status

**Example response**.

.. code-block:: json

    {
        "tasks": {
            "reported": 165,
            "running": 2,
            "total": 167,
            "completed": 0,
            "pending": 0
        },
        "diskspace": {
            "analyses": {
                "total": 491271233536,
                "free": 71403470848,
                "used": 419867762688
            },
            "binaries": {
                "total": 491271233536,
                "free": 71403470848,
                "used": 419867762688
            },
            "temporary": {
                "total": 491271233536,
                "free": 71403470848,
                "used": 419867762688
            }
        },
        "version": "1.0",
        "protocol_version": 1,
        "hostname": "Patient0",
        "machines": {
            "available": 4,
            "total": 5
        }
    }

**Status codes**:

* ``200`` - no error
* ``404`` - machine not found

.. _vpn_status:

/vpn/status
-----------

**GET /vpn/status**

Returns VPN status.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/vpn/status

**Status codes**:

* ``200`` - show status
* ``500`` - not available

.. _exit:

/exit
-----

**GET /exit**

Shuts down the server if in debug mode and using the werkzeug server.

**Example request**.

.. code-block:: bash

    curl -H "Authorization: Bearer S4MPL3" http://localhost:8090/exit

**Status codes**:

* ``200`` - success
* ``403`` - this call can only be used in debug mode
* ``500`` - error
