============
Requirements
============

In order to make Cuckoo run properly in your physical Windows system, you
will have to install some required software and libraries.

Install Python
==============

Python is a strict requirement for the Cuckoo guest component (*analyzer*) in
order to run properly.

You can download the proper Windows installer from the `official website`_.
Also in this case Python 2.7 is preferred.

Some Python libraries are optional and provide some additional features to
Cuckoo guest component. They include:

    * `Python Pillow`_: it's used for taking screenshots of the Windows desktop during the analysis.

They are not strictly required by Cuckoo to work properly, but you are encouraged
to install them if you want to have access to all available features. Make sure
to download and install the proper packages according to your Python version.

.. _`official website`: http://www.python.org/getit/
.. _`Python Pillow`: https://python-pillow.org/


*NOTE*: Physical machinery is currently not supported by the new cuckoo agent.  Please use the old cuckoo agent for physical machinery in the meantime.

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


Additional Host Requirements
============================
The physical machine manager uses RPC requests to reboot physical machines.
The `net` command is required for this to be accomplished, and is available
from the samba-common-bin package.

On Debian/Ubuntu you can install it with::

    $ sudo apt-get install samba-common-bin

In order for the physical machine manager to work, you must have a way
for physical machines to be returned to a clean state. In development/testing
`Fog`_ was used as a platform to handle re-imaging the physical machines.
However, any re-imaging platform can be used (Clonezilla, Deepfreeze, etc) to
accomplish this.

.. _`Fog`: http://www.fogproject.org/

Cuckoo Configuration Requirements
=================================

Since we are using physical machines to perform our analysis, we must account
for the reboot/rebuild time of our physical machines in our Cuckoo configuration.
Specifically, we must modify the vm_state timeout as specified in conf/cuckoo.conf::

	vm_state = 60

By default, this value is set to 60 (seconds). We need to update it so that it
reflects the amount of time required to reboot and rebuild the physical guest.
In testing 10 minutes (i.e., vm_state = 600) has proven sufficient, provided a
Windows 7 setup with a 1 gbit connection. However, it is recommended that you
analyze the time it takes to reboot/rebuild the phyical machine in your
environment before setting this value.
