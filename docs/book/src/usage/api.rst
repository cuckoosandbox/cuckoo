========
REST API
========

As mentioned in :doc:`submit`, Cuckoo provides a simple and lightweight REST
API server implemented in `Bottle.py`_, therefore in order to make the service
work you'll need it installed, Bottle release must be 0.10 or above.

On Debian/Ubuntu::

    $ sudo apt-get install python-bottle

With Pip::

    $ pip install bottle

.. _`Bottle.py`: http://www.bottlepy.org

Starting the API server
=======================

In order to start the API server you can simply do::

    $ ./utils/api.py

By default it will bind the service on **localhost:8090**. If you want to change those values, you can for example with::

    $ ./utils/api.py --host 0.0.0.0 --port 1337

Resources
=========

Following is a list of currently available resources and a brief description. For details click on the resource name.

+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| Resource                          | Description                                                                                                      |
+===================================+==================================================================================================================+
| ``POST`` :ref:`tasks_create_file` | Adds a file to the list of pending tasks to be processed and analyzed.                                           |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``POST`` :ref:`tasks_create_url`  | Adds an URL to the list of pending tasks to be processed and analyzed.                                           |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_list`         | Returns the list of tasks stored in the internal Cuckoo database.                                                |
|                                   | You can optionally specify a limit of entries to return.                                                         |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_view`         | Returns the details on the task assigned to the specified ID.                                                    |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_delete`       | Removes the given task from the database and deletes the results.                                                |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`tasks_report`       | Returns the report generated out of the analysis of the task associated with the specified ID.                   |
|                                   | You can optionally specify which report format to return, if none is specified the JSON report will be returned. |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`files_view`         | Search the analyzed binaries by MD5 hash, SHA256 hash or internal ID (referenced by the tasks details).          |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`files_get`          | Returns the content of the binary with the specified SHA256 hash.                                                |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`machines_list`      | Returns the list of analysis machines available to Cuckoo.                                                       |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`machines_view`      | Returns details on the analysis machine associated with the specified name.                                      |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+
| ``GET`` :ref:`cuckoo_status`      | Returns the basic cuckoo status, including version and tasks overview                                            |
+-----------------------------------+------------------------------------------------------------------------------------------------------------------+


.. _tasks_create_file:

/tasks/create/file
------------------

    **POST /tasks/create/file**

        Adds a file to the list of pending tasks. Returns the ID of the newly created task.

        **Example request**::

            curl -F file=@/path/to/file http://localhost:8090/tasks/create/file

        **Example response**::

            {
                "task_id" : 1
            }

        **Form parameters**:
            * ``file`` *(required)* - path to the file to submit
            * ``package`` *(optional)* - analysis package to be used for the analysis
            * ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
            * ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
            * ``options`` *(optional)* - options to pass to the analysis package
            * ``machine`` *(optional)* - ID of the analysis machine to use for the analysis
            * ``platform`` *(optional)* - name of the platform to select the analysis machine from (e.g. "windows")
            * ``tags`` *(optional)* - define machine to start by tags. Platform must be set to use that. Tags are comma separated
            * ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
            * ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
            * ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
            * ``clock`` *(optional)* - set virtual machine clock (format %m-%d-%Y %H:%M:%S)

        **Status codes**:
            * ``200`` - no error

.. _tasks_create_url:

/tasks/create/url
-----------------

    **POST /tasks/create/url**

        Adds a file to the list of pending tasks. Returns the ID of the newly created task.

        **Example request**::

            curl -F url="http://www.malicious.site" http://localhost:8090/tasks/create/url

        **Example response**::

            {
                "task_id" : 1
            }

        **Form parameters**:
            * ``url`` *(required)* - URL to analyze
            * ``package`` *(optional)* - analysis package to be used for the analysis
            * ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
            * ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
            * ``options`` *(optional)* - options to pass to the analysis package
            * ``machine`` *(optional)* - ID of the analysis machine to use for the analysis
            * ``platform`` *(optional)* - name of the platform to select the analysis machine from (e.g. "windows")
            * ``tags`` *(optional)* - define machine to start by tags. Platform must be set to use that. Tags are comma separated
            * ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
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

        **Example request**::

            curl http://localhost:8090/tasks/list

        **Example response**::

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

.. _tasks_view:

/tasks/view
-----------

    **GET /tasks/view/** *(int: id)*

        Returns details on the task associated with the specified ID.

        **Example request**::

            curl http://localhost:8090/tasks/view/1

        **Example response**::

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

        **Parameters**:
            * ``id`` *(required)* *(int)* - ID of the task to lookup

        **Status codes**:
            * ``200`` - no error
            * ``404`` - task not found

.. _tasks_delete:

/tasks/delete
-------------

    **GET /tasks/delete/** *(int: id)*

        Removes the given task from the database and deletes the results.

        **Example request**::

            curl http://localhost:8090/tasks/delete/1

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

        **Example request**::

            curl http://localhost:8090/tasks/report/1

        **Parameters**:
            * ``id`` *(required)* *(int)* - ID of the task to get the report for
            * ``format`` *(optional)* - format of the report to retrieve [json/html/maec/metadata/all/dropped]. If none is specified the JSON report will be returned. ``all`` returns all the result files as tar.bz2, ``dropped`` the dropped files as tar.bz2

        **Status codes**:
            * ``200`` - no error
            * ``400`` - invalid report format
            * ``404`` - report not found

.. _files_view:

/files/view
-----------

    **GET /files/view/md5/** *(str: md5)*

    **GET /files/view/sha256/** *(str: sha256)*

    **GET /files/view/id/** *(int: id)*

        Returns details on the file matching either the specified MD5 hash, SHA256 hash or ID.

        **Example request**::

            curl http://localhost:8090/files/view/id/1

        **Example response**::

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

        **Example request**::

            curl http://localhost:8090/files/get/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 > sample.exe

        **Status codes**:
            * ``200`` - no error
            * ``404`` - file not found

.. _machines_list:

/machines/list
--------------

    **GET /machines/list**

        Returns a list with details on the analysis machines available to Cuckoo.

        **Example request**::

            curl http://localhost:8090/machines/list

        **Example response**::

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

        **Example request**::

            curl http://localhost:8090/machines/view/cuckoo1

        **Example response**::

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

        Returns status of the cuckoo server.

        **Example request**::

            curl http://localhost:8090/cuckoo/status

        **Example response**::

            {
                "tasks": {
                    "reported": 165, 
                    "running": 2, 
                    "total": 167, 
                    "completed": 0, 
                    "pending": 0
                }, 
                "version": "1.0",
                "protocol_version": 1,
                "hostname": "Patient0", 
                "machines": {
                    "available": 4, 
                    "total": 5
                }
                "tools":["vanilla"]
            }
            
        **Status codes**:
            * ``200`` - no error
            * ``404`` - machine not found
