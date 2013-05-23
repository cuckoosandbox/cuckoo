=================
Auxiliary Modules
=================

Cuckoo's auxiliary modules are Python scripts that let you define custom
actions that should be started right before the analysis begins, and stopped
right after the analysis is over. An example of auxiliary module is the
network sniffer (tcpdump).

You can create as many modules as you want, as long as they follow a
predefined structure that we will present in this chapter.

Getting started
===============

When a new analysis is started, Cuckoo will invoke all the auxiliary modules
available in the *modules/auxiliaries/* directory. Any additional module you
decide to create, must be placed inside that directory.

Every module should also have a dedicated section in the file *conf/auxiliaries.conf*:
for example if you create a module *module/auxiliaries/foobar.py* you will have to append
the following section to *conf/auxiliaries.conf*::

    [foobar]
    enabled = on

Every module will then be initialized and started before the virtual machine
is reverted to snapshot, and stopped after the virtual machine gets shut down.

A basic auxiliary module could look like:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Auxiliary

        class MyModule(Auxiliary):

            def start(self):
                result = start_something()
                if result:
                    return True
                else:
                    return False
            
            def stop(self):
                result = stop_something()
                if result:
                    return True
                else:
                    return False

Every processing module should contain:
    * A class inheriting ``Auxiliary``.
    * A ``start()`` function, that should return True or False to indicate whether it succeeded or not.
    * A ``stop()`` function, that should return True or False to indicate whether it succeeded or not.

You can also specify an ``order`` value, which allows you to run the available auxiliary modules
in an ordered sequence. By default all modules are set with an ``order`` value of ``1`` and are executed
in alphabetical order.

If you want to change this value your module would look like:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Auxiliary

        class MyModule(Auxiliary):
            order = 2

            def start(self):
                result = start_something()
                if result:
                    return True
                else:
                    return False
            
            def stop(self):
                result = stop_something()
                if result:
                    return True
                else:
                    return False

You can also manually disable an auxiliary module by setting the ``enabled`` attribute to ``False``:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Auxiliary

        class MyModule(Auxiliary):
            enabled = False

            def start(self):
                result = start_something()
                if result:
                    return True
                else:
                    return False
            
            def stop(self):
                result = stop_something()
                if result:
                    return True
                else:
                    return False

The auxiliary modules are provided with some attributes that can be used to configure the tools you are launching
(for example defining command line options and so on):

    * ``self.analysis_path``: path to the folder where the results should go (e.g. *storage/analysis/1*).
    * ``self.task``: a dictionary containing all the current task info.
    * ``self.machine``: a dictionary containing all the current virtual machine info.
    * ``self.options``: a dictionary containing all the configuration options for the current module (from the appropriate section in *conf/auxiliaries.conf*).

