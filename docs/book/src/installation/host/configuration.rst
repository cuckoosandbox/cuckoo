=============
Configuration
=============

Cuckoo relies on six main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`auxiliary_conf`: for enabling and configuring auxiliary modules.
    * :ref:`machinery_conf`: for defining the options for your virtualization software
        (the file has the same name of the machinery module you choose in cuckoo.conf).
    * :ref:`memory_conf`: Volatility configuration.
    * :ref:`processing_conf`: for enabling and configuring processing modules.
    * :ref:`reporting_conf`: for enabling or disabling report formats.

To get Cuckoo working you have to edit :ref:`auxiliary_conf`:, :ref:`cuckoo_conf` and :ref:`machinery_conf` at least.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, it contains the generic configuration
options that you might want to verify before launching Cuckoo.

The file is largely commented and self-explaining, but some of the options you might
want to pay more attention to are:

    * ``machinery`` in ``[cuckoo]``: this defines which Machinery module you want Cuckoo to use to interact with your analysis machines. The value must be the name of the module without extension.
    * ``ip`` and ``port`` in ``[resultserver]``: defines the local IP address and port that Cuckoo is going to use to bind the result server on. Make sure this matches the network configuration of your analysis machines, or they won't be able to return the collected results.
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

    # We used to define the network interface to capture on in auxiliary.conf, but
    # this has been moved to the "interface" field of each Virtual Machinery
    # configuration.

    # Specify a Berkeley packet filter to pass to tcpdump.
    # Note: packer filtering is not possible when using "nictrace" functionality
    # from VirtualBox (for example dumping inter-VM traffic).
    # bpf = not arp

    [mitm]
    # Enable man in the middle proxying (mitmdump) [yes/no].
    enabled = no

    # Specify the path to your local installation of mitmdump. Make sure this
    # path is correct.
    mitmdump = /usr/local/bin/mitmdump

    # Listen port base. Each virtual machine will use its own port to be
    # able to make a good distinction between the various running analyses.
    # Generally port 50000 should be fine, in this case port 50001, 50002, etc
    # will also be used - again, one port per analyses.
    port_base = 50000

    # Script file to interact with the network traffic. Please refer to the
    # documentation of mitmproxy/mitmdump to get an understand of their internal
    # workings. (https://mitmproxy.org/doc/scripting/inlinescripts.html)
    script = data/mitm.py

    # Path to the certificate to be used by mitmdump. This file will be
    # automatically generated for you if you run mitmdump once. It's just that
    # you have to copy it from ~/.mitmproxy/mitmproxy-ca-cert.p12 to somewhere
    # in the analyzer/windows/ directory. Recommended is to write the certificate
    # to analyzer/windows/bin/cert.p12, in that case the following option should
    # be set to bin/cert.p12.
    certificate = bin/cert.p12

    [services]
    # Provide extra services accessible through the network of the analysis VM
    # provided in separate, standalone, Virtual Machines [yes/no].
    enabled = no

    # Comma-separated list with each Virtual Machine containing said service(s).
    services = honeyd

    # Time in seconds required to boot these virtual machines. E.g., some services
    # will only get online after a minute because initialization takes a while.
    timeout = 0

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
    mode = headless

    # Path to the local installation of the VBoxManage utility.
    path = /usr/bin/VBoxManage

    # Default network interface.
    interface = vboxnet0

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
    # overrides the default interface specified in auxiliary.conf
    # Example (vboxnet0 is the interface name):
    # interface = vboxnet0

    # (Optional) Specify the IP of the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here
    # the IP address for the Result Server as your machine sees it. If you don't specify an
    # address here, the machine will use the default value from cuckoo.conf.
    # NOTE: if you set this option you have to set result server IP to 0.0.0.0 in cuckoo.conf.
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

    [honeyd]
    # For more information on this VM please refer to the "services" section of
    # the conf/auxiliary.conf configuration file. This machine is a bit special
    # in the way that its used as an additional VM for an analysis.
    # *NOTE* that if this functionality is used, the VM should be registered in
    # the "machines" list in the beginning of this file.
    label = honeyd
    platform = linux
    ip = 192.168.56.102
    # The tags should at least contain "service" and the name of this service.
    # This way the services auxiliary module knows how to find this particular VM.
    tags = service, honeyd
    # Not all services actually have a Cuckoo Agent running in the VM, for those
    # services one can specify the "noagent" option so Cuckoo will just wait until
    # the end of the analysis instead of trying to connect to the non-existing
    # Cuckoo Agent. We can't really intercept any inter-VM communication from the
    # host / gateway so in order to dump traffic between VMs we have to use a
    # different network dumping approach. For this machine we use the "nictrace"
    # functionality from VirtualBox (which is basically their internal tcpdump)
    # and thus properly dumps inter-VM traffic.
    options = nictrace noagent

You can use this same configuration structure for any other machinery module, although
existing ones might have some variations or additional configuration options.

The comments for the options are self-explainatory.

Following is the default *conf/kvm.conf* file::

    [kvm]
    # Specify a comma-separated list of available machines to be used. For each
    # specified ID you have to define a dedicated section containing the details
    # on the respective machine. (E.g. cuckoo1,cuckoo2,cuckoo3)
    machines = cuckoo1

    # Specify the name of the default network interface that will be used
    # when dumping network traffic with tcpdump.
    # Example (virbr0 is the interface name):
    interface = virbr0

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
    # when dumping network traffic from this machine with tcpdump.
    # Example (virbr0 is the interface name):
    # interface = virbr0

    # (Optional) Specify the IP of the Result Server, as your virtual machine sees it.
    # The Result Server will always bind to the address and port specified in cuckoo.conf,
    # however you could set up your virtual network to use NAT/PAT, so you can specify here
    # the IP address for the Result Server as your machine sees it. If you don't specify an
    # address here, the machine will use the default value from cuckoo.conf.
    # NOTE: if you set this option you have to set result server IP to 0.0.0.0 in cuckoo.conf.
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
===========

The Volatility tool offers a large set of plugins for memory dump analysis. Some of them are quite slow.
In volatility.conf lets you to enable or disable the plugins of your choice.
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

The filter configuration helps you to remove known clean data from the resulting
report. It can be configured separately for every plugin.

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

    [apkinfo]
    enabled = no
    # Decompiling dex files with androguard in a heavy operation. For large dex
    # files it can really take quite a while - it is recommended to limit to a
    # certain filesize.
    # decompilation_threshold=5000000

    [baseline]
    enabled = no

    [behavior]
    enabled = yes

    [buffer]
    enabled = yes

    [debug]
    enabled = yes

    [droidmon]
    enabled = no

    [dropped]
    enabled = yes

    [dumptls]
    enabled = yes

    [googleplay]
    enabled = no
    android_id =
    google_login =
    google_password =

    [memory]
    # Create a memory dump of the entire Virtual Machine. This memory dump will
    # then be analyzed using Volatility to locate interesting events that can be
    # extracted from memory.
    enabled = no

    [network]
    enabled = yes

    [procmemory]
    # Enables the creation of process memory dumps for each analyzed process right
    # before they terminate themselves or right before the analysis finishes.
    enabled = yes
    # It is possible to load these process memory dumps in IDA Pro through the
    # generation of IDA Python-based script files. Although currently symbols and
    # such are not properly recovered, it is still nice to get a quick look at
    # specific memory addresses of a process.
    idapro = no

    [screenshots]
    enabled = no
    tesseract = /usr/bin/tesseract

    [snort]
    enabled = no
    # Following are various configurable settings. When in use of a recent 2.9.x.y
    # version of Snort there is no need to change any of the following settings as
    # they represent the defaults.
    #
    # snort = /usr/local/bin/snort
    # conf = /etc/snort/snort.conf

    [static]
    enabled = yes

    [strings]
    enabled = yes

    [suricata]
    enabled = no
    # Following are various configurable settings. When in use of a recent version
    # of Suricata there is no need to change any of the following settings as they
    # represent the defaults.
    #
    # suricata = /usr/bin/suricata
    # conf = /etc/suricata/suricata.yaml
    # eve_log = eve.json
    # files_log = files-json.log
    # files_dir = files
    #
    # Uncommenting the following line makes our processing module use the socket
    # mode in Suricata. This is quite the performance improvement as instead of
    # having to load all the Suricata rules for each time the processing module is
    # ran (i.e., for every task), the rules are only loaded once and then we talk
    # to its API. This does require running Suricata as follows or similar;
    # "suricata --unix-socket -D".
    # (Please find more information in utils/suricata.sh for now).
    # socket = /var/run/suricata/cuckoo.socket

    [targetinfo]
    enabled = yes

    [virustotal]
    enabled = yes
    # How much time we can wait to establish VirusTotal connection and get the
    # report.
    timeout = 60
    # Enable this option if you want to submit files to VirusTotal not yet available
    # in their database.
    # NOTE: if you are dealing with sensitive stuff, enabling this option you could
    # leak some files to VirusTotal.
    scan = 0
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
    indent = 4
    encoding = latin-1
    calls = yes

    [reporthtml]
    enabled = no

    [mongodb]
    enabled = no
    host = 127.0.0.1
    port = 27017
    db = cuckoo
    store_memdump = yes
    paginate = 100

    [elasticsearch]
    enabled = no
    # Comma-separated list of ElasticSearch hosts.
    hosts = 127.0.0.1
    # Set to yes if we want to be able to search every API call instead of just
    # through the behavioral summary.
    calls = no
    # Index of this Cuckoo instance. If multiple Cuckoo instances connect to the
    # same ElasticSearch host then this index (in Moloch called "instance") should
    # be unique for each Cuckoo instance.
    #
    # index = cuckoo
    #
    # Just in case we will have report updates in Cuckoo one will be able to
    # update to a new scheme by modifying the ElasticSearch document type.
    #
    # type = cuckoo

    [moloch]
    enabled = no
    # If the Moloch web interface is hosted on a different IP address than the
    # Cuckoo Web Interface then you'll want to override the IP address here.
    # host = 127.0.0.1
    #
    # Following are various configurable settings. When in use of a recent version
    # of Moloch there is no need to change any of the following settings as they
    # represent the defaults.
    #
    # moloch_capture = /data/moloch/bin/moloch-capture
    # conf = /data/moloch/etc/config.ini
    # instance = cuckoo

By setting those option to *on* or *off* you enable or disable the generation
of such reports.
