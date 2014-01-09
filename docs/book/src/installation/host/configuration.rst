=============
Configuration
=============

Cuckoo relies on six main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`auxiliary_conf`: for enabling and configuring auxiliary modules.
    * :ref:`machinery_conf`: for defining the options for your virtualization software
        (the file has the same name of the machinery module you choose in cuckoo.conf).
    * :ref:`memory_conf`: Volatility configuration
    * :ref:`processing_conf`: for enabling and configuring processing modules.
    * :ref:`reporting_conf`: for enabling or disabling report formats.

To get Cuckoo working you have to edit :ref:`auxiliary_conf`:, :ref:`cuckoo_conf` and :ref:`machinery_conf` at least.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, it contains the generic configuration
options that you might want to verify before launching Cuckoo.

The file is largely commented and self-explainatory, but some of the options you might
want to pay more attention to are:

    * ``machinery`` in ``[cuckoo]``: this defines which Machinery module you want Cuckoo to use to interact with your analysis machines. The value must be the name of the module without extention.
    * ``ip`` and ``port`` in ``[resultserver]``: defines the local IP address and port that Cuckoo is going to use to bind the result server on. Make sure this is aligned with the network configuration of your analysis machines, or they won't be able to return the collected results.
    * ``connection`` in ``[database]``: defines how to connect to the internal database. You can use any DBMS supported by `SQLAlchemy`_ using a valid `Database Urls`_ syntax.

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

Auxiliary modules are scripts that run concurrently with malware analysis, this file defines
their options.

Following is the default *conf/auxiliary.conf* file::

    [sniffer]
    # Enable or disable the use of an external sniffer (tcpdump) [yes/no].
    enabled = yes

    # Specify the path to your local installation of tcpdump. Make sure this
    # path is correct.
    tcpdump = /usr/sbin/tcpdump

    # Specify the network interface name on which tcpdump should monitor the
    # traffic. Make sure the interface is active.
    interface = vboxnet0

    # Specify a Berkeley packet filter to pass to tcpdump.
    # bpf = not arp

.. _machinery_conf:

<machinery>.conf
================

Machinery modules are scripts that define how Cuckoo should interact with
your virtualization software of choice.

Every module should have a dedicated configuration file which defines the
details on the available machines. For example, if you created a *vmware.py*
machinery module, you should specify *vmware* in *conf/cuckoo.conf*
and have a *conf/vmware.conf* file.

Cuckoo provides some modules by default and for the sake of this guide, we'll
assume you're going to use VirtualBox.

Following is the default *conf/virtualbox.conf* file::

    [virtualbox]
    # Specify which VirtualBox mode you want to run your machines on.
    # Can be "gui", "sdl" or "headless". Refer to VirtualBox's official
    # documentation to understand the differences.
    mode = gui

    # Path to the local installation of the VBoxManage utility.
    path = /usr/bin/VBoxManage

    # Specify a comma-separated list of available machines to be used. For each
    # specified ID you have to define a dedicated section containing the details
    # on the respective machine. (E.g. cuckoo1,cuckoo2,cuckoo3)
    machines = cuckoo1

    [cuckoo1]
    # Specify the label name of the current machine as specified in your
    # VirtualBox configuration.
    label = cuckoo1 

    # Specify the operating system platform used by current machine
    # [windows/darwin/linux].
    platform = windows

    # Specify the IP address of the current virtual machine. Make sure that the
    # IP address is valid and that the host machine is able to reach it. If not,
    # the analysis will fail.
    ip = 192.168.56.101
    
    # (Optional) Specify the snapshot name to use. If you do not specify a snapshot
    # name, the VirtualBox MachineManager will use the current snapshot.
    # Example (Snapshot1 is the snapshot name):
    # snapshot = Snapshot1

    # (Optional) Specify the name of the network interface that should be used
    # when dumping network traffic from this machine with tcpdump. If specified,
    # overrides the default interface specified in cuckoo.conf
    # Example (virbr0 is the interface name):
    # interface = virbr0
    
    # (Optional) Specify the IP of the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here 
    # the IP address for the Result Server as your machine sees it. If you don't specify an
    # address here, the machine will use the default value from cuckoo.conf.
    # Example:
    # resultserver_ip = 192.168.56.1

    # (Optional) Specify the port for the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here
    # the port for the Result Server as your machine sees it. If you don't specify a port
    # here, the machine will use the default value from cuckoo.conf.
    # Example:
    # resultserver_port = 2042

    # (Optional) Set your own tags. These are comma separated and help to identify
    # specific VMs. You can run samples on VMs with tag you require.
    # tags = windows_xp_sp3,32_bit,acrobat_reader_6

You can use this same configuration structure for any other machinery module, although
existing ones might have some variations or additional configuration options.

The comments for the options are self-explainatory.

Following is the default *conf/kvm.conf* file::

    [kvm]
    # Specify a comma-separated list of available machines to be used. For each
    # specified ID you have to define a dedicated section containing the details
    # on the respective machine. (E.g. cuckoo1,cuckoo2,cuckoo3)
    machines = cuckoo1

    [cuckoo1]
    # Specify the label name of the current machine as specified in your
    # libvirt configuration.
    label = cuckoo1

    # Specify the operating system platform used by current machine
    # [windows/darwin/linux].
    platform = windows

    # Specify the IP address of the current virtual machine. Make sure that the
    # IP address is valid and that the host machine is able to reach it. If not,
    # the analysis will fail. You may want to configure your network settings in
    # /etc/libvirt/<hypervisor>/networks/
    ip = 192.168.122.105
    
    # (Optional) Specify the snapshot name to use. If you do not specify a snapshot
    # name, the KVM MachineManager will use the current snapshot.
    # Example (Snapshot1 is the snapshot name):
    # snapshot = Snapshot1

    # (Optional) Specify the name of the network interface that should be used
    # when dumping network traffic from this machine with tcpdump. If specified,
    # overrides the default interface specified in cuckoo.conf
    # Example (virbr0 is the interface name):
    # interface = virbr0

    # (Optional) Specify the IP of the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here 
    # the IP address for the Result Server as your machine sees it. If you don't specify an
    # address here, the machine will use the default value from cuckoo.conf.
    # Example:
    # resultserver_ip = 192.168.122.101

    # (Optional) Specify the port for the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here
    # the port for the Result Server as your machine sees it. If you don't specify a port
    # here, the machine will use the default value from cuckoo.conf.
    # Example:
    # resultserver_port = 2042

    # (Optional) Set your own tags. These are comma separated and help to identify
    # specific VMs. You can run samples on VMs with tag you require.
    # tags = windows_xp_sp3,32_bit,acrobat_reader_6

.. _memory_conf:

memory.conf
===============

The volatility tool offers a large set of plugins for memory dump analysis. Some of them are quite slow.
In volatility.conf enables you to enable or disable the plugins of your choice.
To use Volatility you have to follow two steps:
 * Enable it before in processing.conf
 * Enable memory_dump in cuckoo.conf

In the memory.conf's basic section you can configure the Volatility profile and
the deletion of memory dumps after processing::

    # Basic settings
    [basic]
    # Profile to avoid wasting time identifying it
    guest_profile = WinXPSP2x86
    # Delete memory dump after volatility processing.
    delete_memdump = no

After that every plugin has an own section for configuration::

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

The filter configuration helps you to remove known clean data from the resulting report. It can be configured seperately for every plugin.

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
These modules are located under `modules/processing/` and define how to digest
the raw data collected during the analysis.

You will find a section for each processing module::

    # Enable or disable the available processing modules [on/off].
    # If you add a custom processing module to your Cuckoo setup, you have to add
    # a dedicated entry in this file, or it won't be executed.
    # You can also add additional options under the section of your module and
    # they will be available in your Python class.

    [analysisinfo]
    enabled = yes

    [behavior]
    enabled = yes

    [debug]
    enabled = yes

    [dropped]
    enabled = yes

    [memory]
    enabled = no

    [network]
    enabled = yes

    [static]
    enabled = yes

    [strings]
    enabled = yes

    [targetinfo]
    enabled = yes

    [virustotal]
    enabled = yes
    # Add your VirusTotal API key here. The default API key, kindly provided
    # by the VirusTotal team, should enable you with a sufficient throughput
    # and while being shared with all our users, it shouldn't affect your use.
    key = a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088

You might want to configure the `VirusTotal`_ key if you have an account of your own.

.. _`VirusTotal`: http://www.virustotal.com

.. _reporting_conf:

reporting.conf
==============

The *conf/reporting.conf* file contains information on the automated reports
generation.

It contains the following sections::

    # Enable or disable the available reporting modules [on/off].
    # If you add a custom reporting module to your Cuckoo setup, you have to add
    # a dedicated entry in this file, or it won't be executed.
    # You can also add additional options under the section of your module and
    # they will be available in your Python class.

    [jsondump]
    enabled = yes

    [reporthtml]
    enabled = yes

    [mmdef]
    enabled = no

    [maec40]
    enabled = no
    mode = overview
    processtree = true
    output_handles = false
    static = true
    strings = true
    virustotal = true

    [mongodb]
    enabled = no
    host = 127.0.0.1
    port = 27017

    [hpfclient]
    enabled = no
    host =
    port = 10000
    ident =
    secret =
    channel =

By setting those option to *on* or *off* you enable or disable the generation
of such reports.
