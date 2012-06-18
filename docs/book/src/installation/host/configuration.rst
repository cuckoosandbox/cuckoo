=============
Configuration
=============

Cuckoo relies on two main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`<machinemanager>_conf`: for defining the options for your virtualization software.
    * :ref:`reporting_conf`: for enabling or disabling report formats.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, whose content is::

    [cuckoo]
    # Enable or disable debug logging [on/off].
    debug = off

    # Set the default analysis timeout expressed in seconds. This value will be
    # used to define after how many seconds the analysis will terminate unless
    # otherwise specified at submission.
    analysis_timeout = 120

    # Set the critical timeout expressed in seconds. After this timeout is hit
    # Cuckoo will consider the analysis failed and it will shutdown the machine
    # no matter what. When this happens the analysis results will most likely
    # be lost. Make sure to have a critical_timeout greater than the
    # analysis_timeout.
    critical_timeout = 600

    # If turned on, Cuckoo will delete the original file and will just store a
    # copy in the local binaries repository.
    delete_original = off

    # Specify the name of the machine manager module to use, this module will
    # define the interaction between Cuckoo and your virtualization software
    # of choice.
    machine_manager = virtualbox

    # Enable or disable the use of an external sniffer (tcpdump) [yes/no].
    use_sniffer = yes

    # Specify the path to your local installation of tcpdump. Make sure this
    # path is correct.
    tcpdump = /usr/sbin/tcpdump

    # Specify the network interface name on which tcpdump should monitor the
    # traffic. Make sure the interface is active.
    interface = vboxnet0


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
    # Enable or disable the headless mode [on/off]. If enabled, the graphical user
    # interface will be hidden.
    headless = no

    # Specify a comma-separated list of available machines to be used. For each
    # specified ID you have to define a dedicated section containing the details
    # on the respective machine. (E.g. cuckoo1,cuckoo2,cuckoo3)
    machines = cuckoo1

    [cuckoo1]
    # Specify the label name of the current machine as specified in your
    # VirtualBox configuration.
    label = Cuckoo_1

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
    enabled = on

    [mongodb]
    enabled = on

    [metadata]
    enabled = on

    [maec11]
    enabled = on

By setting those option to *on* or *off* you enable or disable the generation
of such reports.
