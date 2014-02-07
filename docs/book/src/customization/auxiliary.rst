=================
Auxiliary Modules
=================

**Auxiliary** modules define some procedures that need to be executed in parallel
to every single analysis process.
All auxiliary modules should be placed under the *modules/auxiliary/* directory.

The skeleton of a module would look something like this:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Auxiliary

        class MyAuxiliary(Auxiliary):

            def start(self):
                # Do something.

            def stop(self):
                # Stop the execution.

The function ``start()`` will be executed before starting the analysis machine and effectively
executing the submitted malicious file, while the ``stop()`` function will be launched at the
very end of the analysis process, before launching the processing and reporting procedures.

For example, an auxiliary module provided by default in Cuckoo is called *sniffer.py* and
takes care of executing **tcpdump** in order to dump the generated network traffic.
