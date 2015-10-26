============
Requirements
============

In order to make Cuckoo run properly in your virtualized Windows system, you
will have to install some required software and libraries.

Install Python
==============

Python is a strict requirement for the Cuckoo guest component (*analyzer*) in
order to run properly.

You can download the proper Windows installer from the `official website`_.
Also in this case Python 2.7 is preferred.

Some Python libraries are optional and provide some additional features to
Cuckoo guest component. They include:

    * `Python Image Library`_: it's used for taking screenshots of the Windows desktop during the analysis.

They are not strictly required by Cuckoo to work properly, but you are encouraged
to install them if you want to have access to all available features. Make sure
to download and install the proper packages according to your Python version.

.. _`official website`: http://www.python.org/getit/
.. _`Python Image Library`: http://www.pythonware.com/products/pil/

Additional Software
===================

At this point you should have installed everything needed by Cuckoo to run
properly.

Depending on what kind of files you want to analyze and what kind of sandboxed
Windows environment you want to run the malware samples in, you might want to install
additional software such as browsers, PDF readers, office suites etc.
Remember to disable the "auto update" or "check for updates" feature of
any additional software.

This is completely up to you and to what your needs are. You can get some hints
by reading the :doc:`../../introduction/sandboxing` chapter.

