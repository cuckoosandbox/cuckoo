=================
Analysis Packages
=================

The **analysis packages** are a key component in Cuckoo Sandbox.

They consist in structured Python scripts which are executed inside the virtual
machine and that define how Cuckoo should conduct the analysis.

As you already know, you can choose which analysis package to use by specifying
its name at submission time (see :doc:`submit`) like following::

    $ python submit.py /path/to/malware --package <package name>

If none is specified, Cuckoo will try to detect the type of the file and choose
the proper analysis package accordingly. If the file type is not supported and
no package was specified, the analysis will be aborted and marked as failed in
the database.

This functionality allows you not only to use existing analysis packages, but
also create some of your own and customize your Cuckoo setup. Ths topic will
be dealt in details in the :doc:`../customization/packages` customization
chapter.

Cuckoo provides some default analysis packages which include:

    * ``exe``: default analysis package used to analyze generic Windows executables.
    * ``dll``: used to analyze Dynamic Linked Libraries.
    * ``pdf``: used to analyze Adobe Reader while opening the given PDF file.
    * ``doc``: used to analyze Microsoft Office while opening documents.
    * ``php``: used to analyze PHP scripts.
    * ``ie``: used to analyze Internet Explorer while opening the given URL.
    * ``firefox``: used to analyze Mozilla Firefox while opening the given URL.
    * ``tracer``: used to trace assembly instructions performed by the given file.

