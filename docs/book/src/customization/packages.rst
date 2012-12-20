=================
Analysis Packages
=================

As explained in :doc:`../usage/packages`, analysis packages are structured
Python classes that describe how Cuckoo's analyzer component should conduct
the analysis procedure for a given file inside the guest environment.

As you already know, you can create your own packages and add them along with
the default ones.
Designing new packages is very easy and requires just a minimal understanding
of programming and of the Python language.

Getting started
===============

As an example we'll take a look at the default package for analyzing generic
Windows executables (located at *analyzer/windows/packages/exe.py*):

    .. code-block:: python
        :linenos:

        from lib.common.abstracts import Package
        from lib.api.process import Process
        from lib.common.exceptions import CuckooPackageError

        class Exe(Package):
            """EXE analysis package."""

            def start(self, path):
                free = self.options.get("free", False)
                args = self.options.get("arguments", None)
                suspended = True
                if free:
                    suspended = False

                p = Process()
                if not p.execute(path=path, args=args, suspended=suspended):
                    raise CuckooPackageError("Unable to execute initial process, analysis aborted")

                if not free and suspended:
                    p.inject()
                    p.resume()
                    return p.pid
                else:
                    return None

            def check(self):
                return True

            def finish(self):
                return True

Let's walk through the code:
    * Line **1**: import the base ``Package`` class, it's needed to define our analysis package class.
    * Line **2**: import the ``Process`` API class, which is used to create and manipulate Windows processes.
    * Line **3**: import the ``CuckooPackageError`` exception, which is used to notify issues with the execution of the package to the analyzer.
    * Line **5**: define the main class, inheriting ``Package``.
    * Line **8**: define the ``start()`` function, which takes as argument the path to the file to execute.
    * Line **9**: acquire the ``free`` option, which is used to define whether the process should be monitored or not.
    * Line **10**: acquire the ``arguments`` option, which is passed to the creation of the initial process.
    * Line **15**: initialize a ``Process`` instance.
    * Line **16** and **17**: try to execute the malware, if it fails it aborts the execution and notify the analyzer.
    * Line **19**: check if the process should be monitored.
    * Line **20**: inject the process with our DLL.
    * Line **21**: resume the process from the suspended state.
    * Line **22**: return the PID of the newly created process to the analyzer.
    * Line **26**: define the ``check()`` function.
    * Line **29**: define the ``finish()`` function.

``start()``
-----------

In this function you have to place all the initialization operations you want to run.
This might include running the malware process, launching additional applications,
taking memory snapshots and more.

``check()``
-----------

This function is executed by Cuckoo every second while the malware is running.
You can use this function to perform any kind of recurrent operation.

For example if in your analysis you are looking for just one specific indicator to
be created (e.g. a file) you could place your condition in this function and if
it returns ``False``, the analysis will terminate straight away.

Think of it as "should the analysis continue or not?".

For example::

    def check(self):
        if os.path.exists("C:\\config.bin"):
            return False
        else:
            return True

This ``check()`` function will cause Cuckoo to immediately terminate the analysis
whenever *C:\config.bin* is created.

``finish()``
------------

This function is simply called by Cuckoo before terminating the analysis and powering
off the machine.
There's no predefined use for this function and it's not going to affect Cuckoo's
execution whatsoever, so you could simply use it to perform any last operation on
the system.

Options
=======

Every package have automatically access to a dictionary containing all user-specified
options (see :doc:`../usage/submit`).

Such options are made available in the attribute ``self.options``. For example let's
assume that the user specified the following string at submission::

    foo=1,bar=2

The analysis package selected will have access to these values::

    from lib.common.abstracts import Package

    class Example(Package):

        def start(self, path):
            foo = self.options["foo"]
            bar = self.options["bar"]

        def check():
            return True

        def finish():
            return True

These options can be used for anything you might need to configure inside your package.

Process API
===========

The ``Process`` class provides access to different process-related features and functions.
You can import it in your analysis packages with::

    from lib.api.process import Process

You then initialize an instance with::

    p = Process()

In case you want to open an existing process instead of creating a new one, you can
specify multiple arguments:

    * ``pid``: PID of the process you want to operate on.
    * ``h_process``: handle of a process you want to operate on.
    * ``thread_id``: thread ID of a process you want to operate on.
    * ``h_thread``: handle of the thread of a process you want to operate on.

This class implements several methods that you can use in your own scripts.

Methods
-------

.. function:: Process.open()

    Opens an handle to a running process. Returns ``True`` or ``False`` in case of success or failure of the operation.

    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        p.open()
        handle = p.h_process

.. function:: Process.exit_code()

    Returns the exit code of the opened process. If it wasn't already done before, ``exit_code()`` will perform a call to ``open()`` to acquire an handle to the process.

    :rtype: ulong

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        code = p.exit_code()

.. function:: Process.is_alive()

    Calls ``exit_code()`` and verify if the returned code is ``STILL_ACTIVE``, meaning that the given process is still running. Returns ``True`` or ``False``.

    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        if p.is_alive():
            print("Still running!")

.. function:: Process.get_parent_pid()

    Returns the PID of the parent process of the opened process. If it wasn't already done before, ``get_parent_pid()`` will perform a call to ``open()`` to acquire an handle to the process.

    :rtype: int

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        ppid = p.get_parent_pid()

.. function:: Process.execute(path [, args=None[, suspended=False]])

    Executes the file at the specified path. Returns ``True`` or ``False`` in case of success or failure of the operation.

    :param path: path to the file to execute
    :type path: string
    :param args: arguments to pass to the process command line
    :type args: string
    :param suspended: enable or disable suspended mode flag at process creation
    :type suspended: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process()
        p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)

.. function:: Process.resume()

    Resumes the opened process from a suspended state. Returns ``True`` or ``False`` in case of success or failure of the operation.

    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process()
        p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)
        p.resume()

.. function:: Process.terminate()

    Terminates the opened process. Returns ``True`` or ``False`` in case of success or failure of the operaton.

    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        if p.terminate():
            print("Process terminated!")
        else:
            print("Could not terminate the process!")

.. function:: Process.inject([dll[, apc=False]])

    Injects a DLL (by default "dll/cuckoomon.dll") into the opened process. Returns ``True`` or ``False`` in case of success or failure of the operation.

    :param dll: path to the DLL to inject into the process
    :type dll: string
    :param apc: enable to use ``QueueUserAPC()`` injection istead of ``CreateRemoteThread()``, beware that if the process is in suspended mode, Cuckoo will always use ``QueueUserAPC()``
    :type apc: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process()
        p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)
        p.inject()
        p.resume()

.. function:: Process.dump_memory()

    Takes a snapshot of the given process' memory space. Returns ``True`` or ``False`` in case of success or failure of the operation.

    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        p = Process(pid=1234)
        p.dump_memory()
