=================
Analysis Packages
=================

As explained in :doc:`../usage/packages`, analysis packages are structured
Python scripts that allow you to customize the analysis procedure inside the
virtualized Windows environment.

By default Cuckoo provides some default packages you can already use, but you
are able to create and use some of your own.

Creating new packages is really easy and just requires minimal knowledge of the
Python language.

Getting started
===============

As first example we'll take a look at the default package for analyzing generic
Windows executables (located at *shares/setup/packages/exe.py*):

    .. code-block:: python
        :linenos:

        import os
        import sys

        sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

        from cuckoo.execute import cuckoo_execute
        from cuckoo.monitor import cuckoo_monitor

        # The package main function "cuckoo_run" should follow a fixed structure in
        # order for Cuckoo to correctly handle it and its results.
        def cuckoo_run(target_path):
            # Every analysis package can retrieve a list of multiple process IDs it
            # might have generated. All processes added to this list will be added to
            # the monitored list, and Cuckoo will wait for all of the to complete their
            # execution before ending the analysis.
            pids = []

            # The following functions are used to launch a process with the simplified
            # "cuckoo_execute" function. This function takes as arguments (in specific
            # order):
            # - a path to the executable to launch
            # - arguments to be passed on execution
            # - a boolean value to specify if the process have to be created in
            #   suspended mode or not (it's recommended to set it to True if the
            #   process is supposed to be injected and monitored).
            suspended = True
            (pid, h_thread) = cuckoo_execute(target_path, None, suspended)

            # The function "cuckoo_monitor" invoke the DLL injection and resume the
            # process if it was suspended. It needs the process id and the main thread
            # handle returned by "cuckoo_execute" and the same boolean value to tell it
            # if it needs to resume the process.
            cuckoo_monitor(pid, h_thread, suspended)

            # Append all the process IDs you want to the list, and return the list.
            pids.append(pid)
            return pids

        def cuckoo_check():
            return True

        def cuckoo_finish():
            return True

Let's walk through the given code.

At line **1** and **2** we import the ``os`` and ``sys`` Python modules.
At line **4** we append "*\\\\VBOXSVR\\setup\\lib\\*" to Python's modules paths list:
this will allow us to invoke Cuckoo's modules directly from the shared folder.

Then we can see that three functions are defined:

    * :ref:`cuckoo_run`
    * :ref:`cuckoo_check`
    * :ref:`cuckoo_finish`

In the given example the package just executes the binary located at ``target_path``
in suspended mode and instructs Cuckoo to inject the process and start
monitoring it.

A slightly more complex example is the PDF analysis package (located at
*shares/setup/packages/pdf.py*):

    .. code-block:: python
        :linenos:

        import os
        import sys

        sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

        from cuckoo.execute import cuckoo_execute
        from cuckoo.monitor import cuckoo_monitor

        def cuckoo_run(target_path):
            pids = []

            # Customize this Path with the correct one on your Windows setup.
            adobe_reader = "C:\\Program Files\\Adobe\\Reader 9.0\\Reader\\AcroRd32.exe"

            suspended = True
            (pid, h_thread) = cuckoo_execute(adobe_reader, "\"%s\"" % target_path, suspended)
            cuckoo_monitor(pid, h_thread, suspended)

            pids.append(pid)
            return pids

        def cuckoo_check():
            return True

        def cuckoo_finish():
            return True

In this example we have the same structure, with the only difference being that
instead of executing the file at *target_path*, it executes Adobe Reader with
*target_path* as argument. In this way it basically instructs Cuckoo to monitor
what Adobe Reader is doing while opening the given PDF file. As you understand,
this opens a large spectrum of possibilities on what Cuckoo can be used for.

.. _cuckoo_run:

``cuckoo_run()``
----------------

This function is the starting point of the analysis. In this block you
should define every operation that should performed as initialization of the
analysis.

This could include the execution of processes, creation of files, injection of
processes and whatever you might need to perform.

It should return a list of PIDs that will be used by Cuckoo to monitor their
process status: when all monitored processes complete their execution, Cuckoo
will terminate the analysis and exit earlier.
If none are returned, Cuckoo will assume that there is no
process monitored and will just run for the amount of seconds specified by
the analysis timeout.

.. _cuckoo_check:

``cuckoo_check()``
------------------

This function is performed regularly every second during the analysis. It can
be used to perform custom checks or any other operation needed.

If the ``cuckoo_check()`` function returns *False*, Cuckoo will assume that the
package matched a conditional check and it will terminate the analysis earlier.

.. _cuckoo_finish:

``cuckoo_finish()``
-------------------

This function is executed when the analysis is completed. It can be used for any
post-analysis purpose such as copying files or any other operation you might
need to perform before the virtual machine is shut down.

Cuckoo Modules
==============

As you noticed in the packages examples, Cuckoo provides some custom functions
that facilitates some complex Windows actions.

These functions are defined in some Python modules that Cuckoo provide by
default. You can use any of these modules in your analysis packages.

Following is a list of available modules and the contained functions.

``cuckoo.checkprocess``
-----------------------

* **Function** ``check_process()``:

    **Prototype**:

    .. code-block:: python

        def check_process(pid)

    **Description**: check if the specified process is still active and running.

    **Parameter** ``pid``: process ID of the process to check.

    **Return**: True if the process is active, otherwise False.

    **Usage Example**:

    .. code-block:: python
        :linenos:

        from cuckoo.checkprocess import check_process

        if check_process(pid):
            print "Process is active!"
        else:
            print "Process is NOT active!"


``cuckoo.execute``
------------------

* **Function** ``cuckoo_execute()``:

    **Prototype**:

    .. code-block:: python

        def cuckoo_execute(target_path, args = None, suspend = False)

    **Description**: creates a process from the specified file.

    **Parameter** ``target_path``: path to the file to execute.

    **Parameter** ``args``: arguments to pass to the process.

    **Parameter** ``suspend``: set to True if should be created in suspended
    mode, otherwise set to False.

    **Return**: returns a list with PID and thread handle.

    **Usage Example**:

    .. code-block:: python
        :linenos:

        from cuckoo.execute import cuckoo_execute

        (pid, h_thread) = cuckoo_execute("C:\\binary.exe")

``cuckoo.inject``
-----------------

* **Function** ``cuckoo_inject()``:

    **Prototype**:

    .. code-block:: python

        def cuckoo_inject(pid, dll_path)

    **Description**: injects the process with the specified PID with the DLL
    located at *dll_path*.

    **Parameter** ``pid``: ID of the process to inject.

    **Parameter** ``dll_path``: path to the DLL to be injected.

    **Return**: returns True if injection succeeded, otherwise False.

    **Usage Example**:

    .. code-block:: python
        :linenos:

        from cuckoo.inject import cuckoo_inject

        if cuckoo_inject(pid, "C:\\library.dll"):
            print "Process injected successfully!"
        else:
            print "Injection failed!"

``cuckoo.monitor``
------------------

* **Function** ``cuckoo_resumethread()``:

    **Prototype**:

    .. code-block:: python

        def cuckoo_resumethread(h_thread = -1)

    **Description**: resumes a thread from suspended mode.

    **Parameter** ``h_thread``: handle to the thread to be resumed (as returned
    by ``cuckoo_execute()``.

    **Return**: returns True if resume succeeded, otherwise False.

    **Usage Example**:

    .. code-block:: python
        :linenos:

        from cuckoo.monitor import cuckoo_resumethread

        if cuckoo_resumethread(h_thread):
            print "Process resumed!"
        else:
            print "Process resume failed!"

* **Function** ``cuckoo_monitor()``:

    **Prototype**:

    .. code-block:: python

        def cuckoo_monitor(pid = -1, h_thread = -1, suspended = False, dll_path = None)

    **Description**: instructs Cuckoo to inject and monitor the specified process.

    **Parameter** ``pid``: ID of the process to monitor.

    **Parameter** ``h_thread``: handle to the main thread of the process to
    monitor (as returned by ``cuckoo_execute()``).

    **Parameter** ``suspended``: set to True if the process was created
    suspended and has to be resumed, otherwise False.

    **Parameter** ``dll_path`` (optional): path to the DLL to inject into the
    process. If none is specified it will use the default one.

    **Return**: returns True if monitor succeeded, otherwise False.

    **Usage Example**:

    .. code-block:: python
        :linenos:

        from cuckoo.monitor import cuckoo_monitor

        if cuckoo_monitor(pid, h_thread, True):
            print "Process monitoring started successfully!"
        else:
            print "Process monitoring failed!"
