=================
Analysis Packages
=================

The **analysis packages** are a core component of Cuckoo Sandbox.
They consist in structured Python classes which, when executed in the guest machines,
describe how Cuckoo's analyzer component should conduct the analysis.

Cuckoo provides some default analysis packages that you can use, but you are
able to create your own or modify the existing ones. You can find them at
``analyzer/windows/modules/packages/``.

As described in :doc:`../usage/submit`, you can specify some options to the
analysis packages in the form of ``key1=value1,key2=value2``. The existing analysis
packages already include some default options that can be enabled.

Following is a list of the options that work for all analysis packages unless
explicitly stated otherwise:

* ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
* ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
* ``human`` *0*: if disabled, human-like interaction (i.e., mouse movements) will not be enabled

Following is the list of existing packages in alphabetical order:

* ``applet``: used to analyze **Java applets**.

    **Options**:

    * ``class``: specify the name of the class to be executed. This option is mandatory for a correct execution.

* ``bin``: used to analyze generic binary data, such as **shellcodes**.

* ``cpl``: used to analyze **Control Panel Applets**.

* ``dll``: used to run and analyze **Dynamically Linked Libraries**.

    **Options**:

    * ``function``: specify the function to be executed. If none is specified, Cuckoo will try to run ``DllMain``.
    * ``arguments``: specify arguments to pass to the DLL through commandline.
    * ``loader``: specify a process name to use to fake the DLL launcher name instead of rundll32.exe (this is used to fool possible anti-sandboxing tricks of certain malware)

* ``doc``: used to run and analyze **Microsoft Word documents**.

* ``exe``: default analysis package used to analyze generic **Windows executables**.

    **Options**:

    * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.

* ``generic``: used to run and analyze **generic samples** via cmd.exe.

* ``ie``: used to analyze **Internet Explorer**'s behavior when opening the given URL or HTML file.

* ``jar``: used to analyze **Java JAR** containers.

    **Options**:

    * ``class``: specify the path of the class to be executed. If none is specified, Cuckoo will try to execute the main function specified in the Jar's MANIFEST file.

* ``js``: used to run and analyze **Javascript** files (e.g., those found in attachments of emails).

* ``hta``: used to run and analyze **HTML Application** files.

* ``msi``: used to run and analyze **MSI windows installer**.

* ``pdf``: used to run and analyze **PDF documents**.

* ``ppt``: used to run and analyze **Microsoft PowerPoint documents**.

* ``ps1``: used to run and analyze **PowerShell scripts**.

* ``python``: used to run and analyze **Python scripts**.

* ``vbs``: used to run and analyze **VBScript files**.

* ``wsf``: used to run and analyze **Windows Script Host files**.

* ``xls``: used to run and analyze **Microsoft Excel documents**.

* ``zip``: used to run and analyze **Zip archives**.

    **Options**:

    * ``file``: specify the name of the file contained in the archive to execute. If none is specified, Cuckoo will try to execute *sample.exe*.
    * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
    * ``password``: specify the password of the archive. If none is specified, Cuckoo will try to extract the archive without password or use the password "*infected*".

You can find more details on how to start creating new analysis packages in the
:doc:`../customization/packages` customization chapter.

As you already know, you can select which analysis package to use by specifying
its name at submission time (see :doc:`submit`) as follows::

    $ cuckoo submit --package <package name> /path/to/malware

If none is specified, Cuckoo will try to detect the file type and select
the correct analysis package accordingly. If the file type is not supported by
default the analysis will be aborted, therefore we encourage to
specify the package name whenever possible.

For example, to launch a malware and specify some options you can do::

    $ cuckoo submit --package dll --options function=FunctionName,loader=explorer.exe /path/to/malware.dll
