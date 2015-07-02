==================
Submit an Analysis
==================

    * :ref:`submitpy`
    * :ref:`apipy`
    * :ref:`distpy`
    * :ref:`webpy`
    * :ref:`python`

.. _submitpy:

Submission Utility
==================

The easiest way to submit an analysis is to use the provided *submit.py*
command-line utility. It currently has the following options available::

    usage: submit.py [-h] [-d] [--remote REMOTE] [--url] [--package PACKAGE]
                     [--custom CUSTOM] [--owner OWNER] [--timeout TIMEOUT]
                     [--options OPTIONS] [--priority PRIORITY] [--machine MACHINE]
                     [--platform PLATFORM] [--memory] [--enforce-timeout]
                     [--clock CLOCK] [--tags TAGS] [--max MAX] [--pattern PATTERN]
                     [--shuffle] [--unique] [--quiet] [--tool TOOL]
                     [--tool-dir TOOL_DIR]
                     target

    positional arguments:
      target               URL, path to the file or folder to analyze

    optional arguments:
      -h, --help           show this help message and exit
      --remote REMOTE      Specify IP:port to a Cuckoo API server to submit
                           remotely
      --url                Specify whether the target is an URL
      --package PACKAGE    Specify an analysis package
      --custom CUSTOM      Specify any custom value
      --owner OWNER        Specify the task owner
      --timeout TIMEOUT    Specify an analysis timeout
      --options OPTIONS    Specify options for the analysis package (e.g.
                           "name=value,name2=value2")
      --priority PRIORITY  Specify a priority for the analysis represented by an
                           integer
      --machine MACHINE    Specify the identifier of a machine you want to use
      --platform PLATFORM  Specify the operating system platform you want to use
                           (windows/darwin/linux)
      --memory             Enable to take a memory dump of the analysis machine
      --enforce-timeout    Enable to force the analysis to run for the full
                           timeout period
      --clock CLOCK        Set virtual machine clock
      --tags TAGS          Specify tags identifier of a machine you want to use
      --max MAX            Maximum samples to add in a row
      --pattern PATTERN    Pattern of files to submit
      --shuffle            Shuffle samples before submitting them
      --unique             Only submit new samples, ignore duplicates
      --quiet              Only print text on failure
      --tool               Run a tool on the sample
      --tool-dir           Specify location of supporting files for a tool

If you specify a directory as path, all the files contained in it will be
submitted for analysis.

The concept of analysis packages will be dealt later in this documentation (at
:doc:`packages`). Following are some usage examples:

*Example*: submit a local binary::

    $ ./utils/submit.py /path/to/binary

*Example*: submit an URL::

    $ ./utils/submit.py --url http://www.example.com

*Example*: submit a local binary and specify an higher priority::

    $ ./utils/submit.py --priority 5 /path/to/binary

*Example*: submit a local binary and specify a custom analysis timeout of
60 seconds::

    $ ./utils/submit.py --timeout 60 /path/to/binary

*Example*: submit a local binary and specify a custom analysis package::

    $ ./utils/submit.py --package <name of package> /path/to/binary

*Example*: submit a local binary and specify a custom analysis package and
some options (in this case a command line argument for the malware)::

    $ ./utils/submit.py --package exe --options arguments=--dosomething /path/to/binary.exe

*Example*: submit a local binary to be run on virtual machine *cuckoo1*::

    $ ./utils/submit.py --machine cuckoo1 /path/to/binary

*Example*: submit a local binary to be run on a Windows machine::

    $ ./utils/submit.py --platform windows /path/to/binary

*Example*: submit a local binary and take a full memory dump of the analysis machine::

    $ ./utils/submit.py --memory /path/to/binary

*Example*: submit a local binary and force the analysis to be executed for the full timeout (disregarding the internal mechanism that Cuckoo uses to decide when to terminate the analysis)::

    $ ./utils/submit.py --enforce-timeout /path/to/binary

*Example*: submit a local binary and set virtual machine clock. Format is %m-%d-%Y %H:%M:%S. If not specified, the current time is used. For example if we want run a sample the 24 january 2001 at 14:41:20::

    $ ./utils/submit.py --clock "01-24-2001 14:41:20" /path/to/binary

*Example*: submit a sample for Volatility analysis (to reduce side effects of the cuckoo hooking, switch it off with *options free=True*)::

    $ ./utils/submit.py --memory --options free=True /path/to/binary

*Example*: submit a sample and a tool to run on the sample. Cuckoomon is NOT injected into either sample or tool. If the tool requires additional files, use --tool-dir to specify the location on the host.::

	$ ./utils/submit.py --tool /path/to/tool --options tool-options="/F /O" /path/to/binary

.. _webpy:

web.py
======

Cuckoo provides a very small utility under ``utils/web.py``, which will bind a simple
webserver on localhost port 8080, through which you will be able to browse through
existing reports as well as submit new files.

Beware that this is not a full-fledged web interface, which is instead provided
under the folder ``web/`` as a Django-powered application. You can find more details
about that under :doc:`web`.

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
use SQLite, MySQL, PostgreSQL and several other SQL database systems.

Cuckoo is designed to be easily integrated in larger solutions and to be fully
automated. In order to automate analysis submission we suggest to use the REST
API interface described in :doc:`api`, but in case you want to write your
own Python submission script, you can also use the ``add_path()`` and ``add_url()`` functions.

.. function:: add_path(file_path[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, owner=""[, machine=None[, platform=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]]])

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

        >>> from lib.cuckoo.core.database import Database
        >>> db = Database()
        >>> db.add_path("/tmp/malware.exe")
        1
        >>>

.. function:: add_url(url[, timeout=0[, package=None[, options=None[, priority=1[, custom=None[, owner=""[, machine=None[, platform=None[, memory=False[, enforce_timeout=False], clock=None[]]]]]]]]]])

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

    >>> from lib.cuckoo.core.database import Database
    >>> db = Database()
    >>> db.add_url("http://www.cuckoosandbox.org")
    2
    >>>

.. _`SQLAlchemy`: http://www.sqlalchemy.org


Using the tools package
=======================

Generic format::

    submit.py --tool [path] --tool-dir [path] --options tool-options=[options for tool] target

In order to use the tools package, the ``--tool`` argument is required. Following are a description of the arguments shown above: ::

    --tool [path]
    [path] is the full path to the tool on the host machine

    --tool-dir [path]
        [path] is the full path to a directory on the host machine. This directory should contain any files that the tool requires to run

    tool-options=[options]
        [options] should be surrounded by quotes and contain the options needed by the tool.
        If the substring "$sample" is located within [options] it will be replaced with the path to the sample on the guest machine.

    target
        path to the file to analyze

Examples::

    submit.py --tool ~/unpacker.exe ~/malicious.dll
    submit.py --tool ~/pin.exe --tool-dir ~/pin_files --options tool-options="-t veratrace.dll -- " ~/Malware/us.exe

In the last example, the ``pin_files`` directory contains the following files that are required for pin.exe to run:

* veratrace.dll
* pinvm.dll

If the tool is just an .exe file then you wouldn’t need to worry about
``--tool-dir``. ``--tool-dir`` exists in case the tool has additional files
required to run that should also be located on the guest machine (i.e. a dll
file). The files within the specified ``--tool-dir`` will be uploaded to the
same directory as the tool on the sandbox.

The ``tool-options`` argument specifies what the options for the tool should
be. (e.g.  ``-xvf``). If one of the options needs to be the sample, simply
enter ``$sample`` in the correct location in the string (e.g.
``tool-options="/F $sample" /O output.dll``). Arguments (specified by the
"--options arguments=..." will automatically be placed after the sample.
