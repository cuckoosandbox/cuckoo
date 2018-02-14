=============
Configuration
=============

Cuckoo relies on a couple of main configuration files:

* :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
* :ref:`auxiliary_conf`: for enabling and configuring auxiliary modules.
* :ref:`machinery_conf`: for defining the options for your virtualization software (the file has the same name of the machinery module you choose in cuckoo.conf).
* :ref:`memory_conf`: Volatility configuration.
* :ref:`processing_conf`: for enabling and configuring processing modules.
* :ref:`reporting_conf`: for enabling or disabling report formats.

To get Cuckoo working you should at the very least edit :ref:`cuckoo_conf` and
:ref:`machinery_conf`.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is ``$CWD/conf/cuckoo.conf``. Note that we'll be
referring to the :doc:`cwd` when we talk about ``$CWD``. The ``cuckoo.conf``
file contains generic configuration options that you will want to verify or
at least familiarize yourself with before launching Cuckoo.

The file is largely commented and self-explanatory, but some of the options
may be of special interest to you:

* ``machinery`` in ``[cuckoo]``:
    This option defines which Machinery module you want Cuckoo to use to
    interact with your analysis machines. The value must be the name of
    the module without extension (e.g., ``virtualbox`` or ``vmware``).

* ``ip`` and ``port`` in ``[resultserver]``:
    These define the local IP address and port that Cuckoo is going to try
    to bind the result server on. Make sure this matches the network
    configuration of your analysis machines or they won't be able to
    return any results.

* ``connection`` in ``[database]``:
    The database connection string defines how Cuckoo will connect to the
    internal database. You can use any DBMS supported by `SQLAlchemy`_
    using a valid `Database Urls`_ syntax.

.. _`SQLAlchemy`: http://www.sqlalchemy.org/
.. _`Database Urls`: http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

.. warning:: Check your interface for resultserver IP! Some virtualization software (for example Virtualbox)
    don't bring up the virtual networking interfaces until a virtual machine is started.
    Cuckoo needs to have the interface where you bind the resultserver up before the start, so please
    check your network setup. If you are not sure about how to get the interface up, a good trick is to manually start
    and stop an analysis virtual machine, this will bring virtual networking up.
    If you are using NAT/PAT in your network, you can set up the resultserver IP
    to 0.0.0.0 to listen on all interfaces, then use the specific options `resultserver_ip` and `resultserver_port`
    in *<machinery>.conf* to specify the address and port as every machine sees them. Note that if you set
    resultserver IP to 0.0.0.0 in cuckoo.conf you have to set `resultserver_ip` for all your virtual machines.

.. _auxiliary_conf:

auxiliary.conf
==============

Auxiliary modules are scripts that run concurrently with malware analysis,
this file defines their options.

Following is the default ``$CWD/conf/auxiliary.conf`` file.

.. literalinclude:: ../../_files/conf/auxiliary.conf
    :language: ini

.. _machinery_conf:

<machinery>.conf
================

Machinery modules are scripts that define how Cuckoo should interact with
your virtualization software of choice.

Every module has a dedicated configuration file which defines the details on
the available machines. For example, Cuckoo comes with a ``VMWware`` machinery
module. In order to use it one has to specify *vmware* as ``machinery`` option
in ``$CWD/conf/cuckoo.conf`` and populate the ``$CWD/conf/vmware.conf`` file
with the available Virtual Machines.

Cuckoo provides some modules by default and for the sake of this guide, we'll
assume you're going to use VirtualBox.

Following is the default ``$CWD/conf/virtualbox.conf`` file.

.. literalinclude:: ../../_files/conf/virtualbox.conf
    :language: ini

The configuration for the other machinery modules look mostly the same with
some variations where required. E.g., ``XenServer`` operates through an API,
so to access it a URL and credentials are required.

The comments for the options are self-explanatory.

Following is the default ``$CWD/conf/kvm.conf`` file.

.. literalinclude:: ../../_files/conf/kvm.conf
    :language: ini

.. _memory_conf:

memory.conf
===========

The Volatility tool offers a large set of plugins for memory dump analysis.
Some of them are quite slow. The ``$CWD/conf/volatility.conf`` file let's you
enable or disable plugins of your choice. To use Volatility you have to follow
two steps:

 * Enable ``volatility`` in ``$CWD/conf/processing.conf``
 * Enable ``memory_dump`` in ``$CWD/conf/cuckoo.conf``

In ``$CWD/conf/memory.conf``'s basic section you can configure the Volatility
profile and whether memory dumps should be deleted after having been processed
(this saves a lot of diskspace)::

    # Basic settings
    [basic]
    # Profile to avoid wasting time identifying it
    guest_profile = WinXPSP2x86
    # Delete memory dump after volatility processing.
    delete_memdump = no

After that every plugin has its own section for configuration::

    # Scans for hidden/injected code and dlls
    # http://code.google.com/p/volatility/wiki/CommandReference#malfind
    [malfind]
    enabled = on
    filter = on

    # Lists hooked api in user mode and kernel space
    # Expect it to be very slow when enabled
    # http://code.google.com/p/volatility/wiki/CommandReference#apihooks
    [apihooks]
    enabled = off
    filter = on

The filter configuration helps you to remove known clean data from the
resulting report. It can be configured separately for every plugin.

The filter itself is configured in the [mask] section.
You can enter a list of pids in pid_generic to filter out processes::

    # Masks. Data that should not be logged
    # Just get this information from your plain VM Snapshot (without running malware)
    # This will filter out unwanted information in the logs
    [mask]
    # pid_generic: a list of process ids that already existed on the machine before the malware was started.
    pid_generic = 4, 680, 752, 776, 828, 840, 1000, 1052, 1168, 1364, 1428, 1476, 1808, 452, 580, 652, 248, 1992, 1696, 1260, 1656, 1156

.. _processing_conf:

processing.conf
===============

This file allows you to enable, disable and configure all processing modules.
These modules are located under the ``cuckoo.processing`` module and define
how to digest the raw data collected during the analysis.

You will find a section for each processing module in
``$CWD/conf/processing.conf``.

.. literalinclude:: ../../_files/conf/processing.conf
    :language: ini

You might want to configure the `VirusTotal`_ key if you have an account of
your own.

.. _`VirusTotal`: http://www.virustotal.com

.. _reporting_conf:

reporting.conf
==============

The ``$CWD/conf/reporting.conf`` file contains information on the reports
generation.

It contains the following sections.

.. literalinclude:: ../../_files/conf/reporting.conf
    :language: ini

By setting those option to ``on`` or ``off`` you enable or disable the
generation of such reports.
