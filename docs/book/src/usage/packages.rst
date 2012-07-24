=================
Analysis Packages
=================

The **analysis packages** are a core component of Cuckoo Sandbox.

They consist in structured Python classes which, executed in the guest machines,
describe how Cuckoo's analyzer component should conduct the analysis.

Cuckoo provides some default analysis packages that you can use, but you are
able to create your own or eventually modify the existing ones.
You can find them located at *analyzer/windows/packages/*.

Following is the list of existing packages:

    * ``exe``: default analysis package used to analyze generic **Windows executables**.
               You can specify an "arguments" option if you want to pass arguments
               to the process creation (see :doc:`../usage/submit`).
    * ``dll``: used to run and analyze **Dinamically Linked Libraries**.
               You can specify a "function" option that will instruct Cuckoo to
               execute the specified exported function. If this option is not set,
               Cuckoo will try to execute the regular ``DllMain`` function.
               You can also specify a "free" option that will instruct Cuckoo not
               to inject and hook the ``rundll32`` process and let the library run
               (not behavior results will be produced).
    * ``pdf``: used to run and analyze **PDF documents**.
               The path to Acrobat Reader is hardcoded in the package, so make sure
               to verify that it's matches the correct one in your guest environment.
    * ``doc``: used to run and analyze **Microsoft Word documents**.
               Same as the ``pdf`` package, verify Office Word path.
    * ``xls``: used to run and analyze **Microsoft Excel documents**.
               Verify Office Excel path.
    * ``ie``: used to analyze **Internet Explorer**'s behavior when opening the
              given file (e.g. browser exploits).

You can find more details on how to start creating new analysis packages in the
:doc:`../customization/packages` customization chapter.

As you already know, you can select which analysis package to use by specifying
its name at submission time (see :doc:`submit`) like following::

    $ python submit.py --package <package name> /path/to/malware

If none is specified, Cuckoo will try to detect the file type and select
the correct analysis package accordingly. If the file type is not supported by
default the analysis will be aborted, therefore you are always invited to
specify the package name whenever it's possible.