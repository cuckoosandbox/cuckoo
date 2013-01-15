=============
Configuration
=============

Cuckoo relies on three main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`<machinemanager>_conf`: for defining the options for your virtualization software.
    * :ref:`reporting_conf`: for enabling or disabling report formats.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, whose content is::

    [cuckoo]
    # Enable or disable startup version check. When enabled, Cuckoo will connect
    # to a remote location to verify whether the running version is the latest
    # one available.
    version_check = on

    # If turned on, Cuckoo will delete the original file and will just store a
    # copy in the local binaries repository.
    delete_original = off

    # Specify the name of the machine manager module to use, this module will
    # define the interaction between Cuckoo and your virtualization software
    # of choice.
    machine_manager = virtualbox

    # Enable creation of memory dump of the analysis machine before shutting
    # down. Even if turned off, this functionality can also be enabled at
    # submission. Currently available for: VirtualBox and libvirt modules (KVM).
    memory_dump = off

    [processing]
    # Set the maximum size of analysis's generated files to process.
    # This is used to avoid the processing of big files which can bring memory leak.
    # The value is expressed in bytes, by default 100Mb.
    analysis_size_limit = 104857600

    # Enable or disable DNS lookups.
    resolve_dns = on

    [database]
    # Specify the database connection string.
    # Examples, see documentation for more:
    # sqlite:///foo.db
    # postgresql://foo:bar@localhost:5432/mydatabase
    # mysql://foo:bar@localhost/mydatabase
    # If empty, default is a SQLite in  db/cuckoo.db.
    connection =

    # Database connection timeout in seconds.
    # If empty, default is set to 60 seconds.
    timeout =

    [timeouts]
    # Set the default analysis timeout expressed in seconds. This value will be
    # used to define after how many seconds the analysis will terminate unless
    # otherwise specified at submission.
    default = 120

    # Set the critical timeout expressed in seconds. After this timeout is hit
    # Cuckoo will consider the analysis failed and it will shutdown the machine
    # no matter what. When this happens the analysis results will most likely
    # be lost. Make sure to have a critical timeout greater than the
    # default timeout.
    critical = 600

    # Maximum time to wait for virtual machine status change. For example when
    # shutting down a vm. Default is 300 seconds.
    vm_state = 300

    [sniffer]
    # Enable or disable the use of an external sniffer (tcpdump) [yes/no].
    enabled = yes

    # Specify the path to your local installation of tcpdump. Make sure this
    # path is correct.
    tcpdump = /usr/sbin/tcpdump

    # Specify the network interface name on which tcpdump should monitor the
    # traffic. Make sure the interface is active.
    interface = vboxnet0

    [graylog]
    # Enable or disable remote logging to a Graylog2 server.
    enabled = no

    # Graylog2 server host.
    host = localhost

    # Graylog2 server port.
    port = 12201

    # Default logging level for Graylog2. [debug/info/error/critical].
    level = error

The configuration file is self-explainatory.

.. _<machinemanager>_conf:

<machinemanager>.conf
=====================

Machine managers are the modules that define how Cuckoo should interact with
your virtualization software of choice.

Every module should have a dedicated configuration file which defines the
details on the available machines. For example, if you created a *vmware.py*
machine manager module, you should specify *vmware* in *conf/cuckoo.conf*
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

    # Specify the IP address of the current machine. Make sure that the IP address
    # is valid and that the host machine is able to reach it. If not, the analysis
    # will fail.
    ip = 192.168.56.101

You can use this same configuration structure for any other machine manager module.

The comments for the options are self-explainatory.

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
    enabled = on

    [reporthtml]
    enabled = on

    [pickled]
    enabled = off

    [metadata]
    enabled = off

    [maec11]
    enabled = off

    [mongodb]
    enabled = off

    [hpfclient]
    enabled = off
    host = 
    port = 10000
    ident = 
    secret = 
    channel = 

By setting those option to *on* or *off* you enable or disable the generation
of such reports.
