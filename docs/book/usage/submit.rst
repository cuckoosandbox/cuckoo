==================
Submit an Analysis
==================

* :ref:`submitpy`
* :ref:`apipy`
* :ref:`distpy`
* :ref:`python`

.. _submitpy:

Submission Utility
==================

The easiest way to submit an analysis is to use the ``cuckoo submit`` utility.
It currently has the following options available::

    $ cuckoo submit --help
    Usage: cuckoo submit [OPTIONS] [TARGET]...

      Submit one or more files or URLs to Cuckoo.

    Options:
      -u, --url           Submitting URLs instead of samples
      -o, --options TEXT  Options for these tasks
      --package TEXT      Analysis package to use
      --custom TEXT       Custom information to pass along this task
      --owner TEXT        Owner of this task
      --timeout INTEGER   Analysis time in seconds
      --priority INTEGER  Priority of this task
      --machine TEXT      Machine to analyze these tasks on
      --platform TEXT     Analysis platform
      --memory            Enable memory dumping
      --enforce-timeout   Don't terminate the analysis early
      --clock TEXT        Set the system clock
      --tags TEXT         Analysis tags
      --baseline          Create baseline task
      --remote TEXT       Submit to a remote Cuckoo instance
      --shuffle           Shuffle the submitted tasks
      --pattern TEXT      Provide a glob-pattern when submitting a
                          directory
      --max INTEGER       Submit up to X tasks at once
      --unique            Only submit samples that have not been
                          analyzed before
      -d, --debug         Enable verbose logging
      -q, --quiet         Only log warnings and critical messages
      --help              Show this message and exit.

You may specify multiple files or directories at once. For directories
``cuckoo submit`` will enumerate all its files and submit them one by one.

The concept of analysis packages will be dealt later in this documentation (at
:doc:`packages`). Following are some usage examples:

*Example*: submit a local binary::

    $ cuckoo submit /path/to/binary

*Example*: submit an URL::

    $ cuckoo submit --url http://www.example.com

*Example*: submit a local binary and specify an higher priority::

    $ cuckoo submit --priority 5 /path/to/binary

*Example*: submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ cuckoo submit --timeout 60 /path/to/binary

*Example*: submit a local binary and specify a custom analysis package::

    $ cuckoo submit --package <name of package> /path/to/binary

*Example*: submit a local binary and specify a custom route::

    $ cuckoo submit -o route=tor /path/to/binary

*Example*: submit a local binary and specify a custom analysis package and
some options (in this case a command line argument for the malware)::

    $ cuckoo submit --package exe --options arguments=--dosomething /path/to/binary.exe

*Example*: submit a local binary to be run on virtual machine *cuckoo1*::

    $ cuckoo submit --machine cuckoo1 /path/to/binary

*Example*: submit a local binary to be run on a Windows machine::

    $ cuckoo submit --platform windows /path/to/binary

*Example*: submit a local binary and take a full memory dump of the analysis machine::

    $ cuckoo submit --memory /path/to/binary

*Example*: submit a local binary and force the analysis to be executed for the full timeout (disregarding the internal mechanism that Cuckoo uses to decide when to terminate the analysis)::

    $ cuckoo submit --enforce-timeout /path/to/binary

*Example*: submit a local binary and set virtual machine clock. Format is %m-%d-%Y %H:%M:%S. If not specified, the current time is used. For example if we want run a sample the 24 january 2001 at 14:41:20::

    $ cuckoo submit --clock "01-24-2001 14:41:20" /path/to/binary

*Example*: submit a sample for Volatility analysis (to reduce side effects of the cuckoo hooking, switch it off with *options free=True*)::

    $ cuckoo submit --memory --options free=yes /path/to/binary

.. _apipy:

API
===

Detailed usage of the REST API interface is described in :doc:`api`.

.. _distpy:

Distributed Cuckoo
==================

Detailed usage of the Distributed Cuckoo API interface is described in
:doc:`dist`.

.. _python:

Python Functions
================

In order to keep track of submissions, samples and overall execution, Cuckoo
uses a popular Python ORM called `SQLAlchemy`_ that allows you to make the sandbox
use SQLite, MySQL or MariaDB, PostgreSQL and several other SQL database systems.

Cuckoo is designed to be easily integrated in larger solutions and to be fully
automated. In order to automate analysis submission we suggest to use the REST
API interface described in :doc:`api`, but in case you want to write your
own Python submission script, you can also use the ``add_path()`` and ``add_url()`` functions.

.. function:: add_path(file_path[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, owner=""[, machine=None[, platform=None[, tags=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]]]]]])

    Add a local file to the list of pending analysis tasks. Returns the ID of the newly generated task.

    :param file_path: path to the file to submit
    :type file_path: string
    :param timeout: maximum amount of seconds to run the analysis for
    :type timeout: integer
    :param package: analysis package you want to use for the specified file
    :type package: string or None
    :param options: list of options to be passed to the analysis package (in the format ``key=value,key=value``)
    :type options: string or None
    :param priority: numeric representation of the priority to assign to the specified file (1 being low, 2 medium, 3 high)
    :type priority: integer
    :param custom: custom value to be passed over and possibly reused at processing or reporting
    :type custom: string or None
    :param owner: task owner
    :type owner: string or None
    :param machine: Cuckoo identifier of the virtual machine you want to use, if none is specified one will be selected automatically
    :type machine: string or None
    :param platform: operating system platform you want to run the analysis one (currently only Windows)
    :type platform: string or None
    :param tags: tags for machine selection
    :type tags: string or None
    :param memory: set to ``True`` to generate a full memory dump of the analysis machine
    :type memory: True or False
    :param enforce_timeout: set to ``True`` to force the execution for the full timeout
    :type enforce_timeout: True or False
    :param clock: provide a custom clock time to set in the analysis machine
    :type clock: string or None
    :rtype: integer

    Example usage:

    .. code-block:: python
        :linenos:

        >>> from cuckoo.core.database import Database
        >>> db = Database()
        >>> db.add_path("/tmp/malware.exe")
        1
        >>>

.. function:: add_url(url[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, owner=""[, machine=None[, platform=None[, tags=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]]]]]])

    Add a local file to the list of pending analysis tasks. Returns the ID of the newly generated task.

    :param url: URL to analyze
    :type url: string
    :param timeout: maximum amount of seconds to run the analysis for
    :type timeout: integer
    :param package: analysis package you want to use for the specified URL
    :type package: string or None
    :param options: list of options to be passed to the analysis package (in the format ``key=value,key=value``)
    :type options: string or None
    :param priority: numeric representation of the priority to assign to the specified URL (1 being low, 2 medium, 3 high)
    :type priority: integer
    :param custom: custom value to be passed over and possibly reused at processing or reporting
    :type custom: string or None
    :param owner: task owner
    :type owner: string or None
    :param machine: Cuckoo identifier of the virtual machine you want to use, if none is specified one will be selected automatically
    :type machine: string or None
    :param platform: operating system platform you want to run the analysis one (currently only Windows)
    :type platform: string or None
    :param tags: tags for machine selection
    :type tags: string or None
    :param memory: set to ``True`` to generate a full memory dump of the analysis machine
    :type memory: True or False
    :param enforce_timeout: set to ``True`` to force the execution for the full timeout
    :type enforce_timeout: True or False
    :param clock: provide a custom clock time to set in the analysis machine
    :type clock: string or None
    :rtype: integer

Example Usage:

.. code-block:: python
    :linenos:

    >>> from cuckoo.core.database import Database
    >>> db = Database()
    >>> db.connect()
    >>> db.add_url("http://www.cuckoosandbox.org")
    2
    >>>

.. _`SQLAlchemy`: http://www.sqlalchemy.org
