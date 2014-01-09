=================
Analysis Packages
=================

The **analysis packages** are a core component of Cuckoo Sandbox.
They consist in structured Python classes which, executed in the guest machines,
describe how Cuckoo's analyzer component should conduct the analysis.

Cuckoo provides some default analysis packages that you can use, but you are
able to create your own or eventually modify the existing ones.
You can find them located at *analyzer/windows/modules/packages/*.

As described in :doc:`../usage/submit`, you can specify some options to the
analysis packages in the form of ``key1=value1,key2=value2``. The existing analysis
packages already include some default options that can be enabled.

Following is the list of existing packages in alphabetical order:

    * ``applet``: used to analyze **Java applets**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``class``: specify the name of the class to be executed. This option is mandatory for a correct execution.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``bin``: used to analyze generic binary data, such as **shellcodes**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``cpl``: used to analyze **Control Panel Applets**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``dll``: used to run and analyze **Dinamically Linked Libraries**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``function``: specify the function to be executed. If none is specified, Cuckoo will try to run ``DllMain``.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``doc``: used to run and analyze **Microsoft Word documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``exe``: default analysis package used to analyze generic **Windows executables**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``generic``: used to run and analyze **generic samples** via cmd.exe.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``html``: used to analyze **Internet Explorer**'s behavior when opening the given HTML file.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``ie``: used to analyze **Internet Explorer**'s behavior when opening the given URL.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``jar``: used to analyze **Java JAR** containers.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``class``: specify the path of the class to be executed. If none is specified, Cuckoo will try to execute the main function specified in the Jar's MANIFEST file.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``pdf``: used to run and analyze **PDF documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``vbs``: used to run and analyzis **VBScript files**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``xls``: used to run and analyze **Microsoft Excel documents**.

        **Options**:
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

    * ``zip``: used to run and analyze **Zip archives**.

        **Options**:
            * ``file``: specify the name of the file contained in the archive to execute. If none is specified, Cuckoo will try to execute *sample.exe*.
            * ``free`` *[yes/no]*: if enabled, no behavioral logs will be produced and the malware will be executed freely.
            * ``arguments``: specify any command line argument to pass to the initial process of the submitted malware.
            * ``password``: specify the password of the archive. If none is specified, Cuckoo will try to extract the archive without password or use the password "*infected*".
            * ``procmemdump`` *[yes/no]*: if enabled, take memory dumps of all actively monitored processes.
            * ``dll``: specify the name of an optional DLL to be used as a replacement for cuckoomon.dll.

You can find more details on how to start creating new analysis packages in the
:doc:`../customization/packages` customization chapter.

As you already know, you can select which analysis package to use by specifying
its name at submission time (see :doc:`submit`) like following::

    $ ./utils/submit.py --package <package name> /path/to/malware

If none is specified, Cuckoo will try to detect the file type and select
the correct analysis package accordingly. If the file type is not supported by
default the analysis will be aborted, therefore you are always invited to
specify the package name whenever it's possible.

For example, to launch a malware and specify some options you can do::

    $ ./utils/submit.py --package dll --options function=FunctionName /path/to/malware.dll
