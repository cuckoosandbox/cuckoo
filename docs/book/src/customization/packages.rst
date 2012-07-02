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

        class Exe(Package):
            """EXE analysis package."""

            def start(self, path):
                p = Process()

                if "arguments" in self.options:
                    p.execute(path=path, args=self.options["arguments"], suspended=True)
                else:
                    p.execute(path=path, suspended=True)

                p.inject()
                p.resume()

                return p.pid

            def check(self):
                return True

            def finish(self):
                return True

Let's walk through the code.

At line **1** we import the parent class ``Package``, all analysis packages must
inherit this abstract class otherwise Cuckoo won't be able to load them.
At line **2** we import the class ``Process``, which is an API module provided
by Cuckoo's Windows analyzer for accessing several process-related features.

At line **4** we define our class.

At line **7** we define the ``start()`` function, at line **20** the ``check()``
function and at line **23** the ``finish()`` function.
These three functions are required as they are used for customizing the package's
operations at three different stages of the analysis.

In this case we just create a ``Process`` instance, check if the user specified any
arguments as option and launch the malware located at ``path``, which then gets
injected and resumed.

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

``open()``
----------

This method allows you to open an handle to a running process::

    p = Process(pid=1234)
    p.open()
    handle = p.h_process

**Return**: True/False in case of success or failure of the operation.

``exit_code()``
---------------

This method allows you to acquire the exit code of a given process::

    p = Process(pid=1234)
    code = p.exit_code()

If it wasn't already done before, ``exit_code()`` will perform a call
to ``open()`` in order to acquire an handle to the given process.

**Return**: process exit code (ulong).

``is_alive()``
--------------

This method simply calls ``exit_code()`` and verify if the returned code
is ``STILL_ACTIVE``, meaning that the given process is still running::

    p = Process(pid=1234)
    if p.is_alive():
        print("Still running!")

``execute()``
-------------

This method simply allows you to execute a process. It accepts the following
arguments:

    * ``path``: path to the file to execute.
    * ``args``: arguments to pass at process creation.
    * ``suspended``: (True/False) boolean saying if the process should be created in suspended mode or not (default is False)

Example::

    p = Process()
    p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)

**Return**: True/False in case of success or failure of the operation.

``resume()``
------------

This method resumes a process from a suspended state.

Example::

    p = Process()
    p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)
    p.resume()

``terminate()``
---------------

This method allows you to terminate any given process::

    p = Process(pid=1234)
    if p.terminate():
        print("Process terminated!")
    else:
        print("Could not terminate the process!")

**Return**: True/False in case of success or failure of the operation.

``inject()``
------------

This method allows you to inject a DLL file into a given process.
You can specify the following arguments:

    * ``dll``: path to the DLL to inject, if none is specified it will use Cuckoo's default DLL.
    * ``apc``: True/False in case you want to use *QueueUserAPC* injection or not. Default is False, which will result in a *CreateRemoteThread* injection.

Example::

    p = Process()
    p.execute(path="C:\\WINDOWS\\system32\\calc.exe", args="Something", suspended=True)
    p.inject()
    p.resume()

**Return**: True/False in case of success or failure of the operation.

``dump_memory()``
-----------------

This method allows you to take a snapshot of the given process' memory space.
When invoked, it will create a result folder called *memory/<pid>/<timestamp>/* containing
all the dumps sorted as *<memory region address>.dmp* (e.g. *0x12345678.dmp*).

Example::

    p = Process(pid=1234)
    p.dump_memory()

**Return**: True/False in case of success or failure of the operation.