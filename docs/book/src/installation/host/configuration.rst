=============
Configuration
=============

Cuckoo relies on four main configuration files:

    * :ref:`cuckoo_conf`: for configuring general behavior and analysis options.
    * :ref:`<machinemanager>_conf`: for defining the options for your virtualization software.
    * :ref:`processing_conf`: for enabling and configuraing processing modules.
    * :ref:`reporting_conf`: for enabling or disabling report formats.

.. _cuckoo_conf:

cuckoo.conf
===========

The first file to edit is *conf/cuckoo.conf*, it contains the generic configuration
options that you might want to verify before launching Cuckoo.

The file is largely commented and self-explainatory, but some of the options you might
want to pay more attention to are:

    * ``machine_manager`` in ``[cuckoo]``: this defines which Machine Manager module you want Cuckoo to use to interact with your analysis machines. The value must be the name of the module without extention.
    * ``ip`` and ``port`` in ``[resultserver]``: defines the local IP address and port that Cuckoo is going to use to bind the result server on. Make sure this is aligned with the network configuration of your analysis machines, or they won't be able to return the collected results.
    * ``connection`` in ``[database]``: defines how to connect to the internal database. You can use any DBMS supported by `SQLAlchemy`_ using a valid `Database Urls`_ syntax.

.. _`SQLAlchemy`: http://www.sqlalchemy.org/
.. _`Database Urls`: http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

.. warning:: Check your interface for resultserver IP! Some virtualization software (for example Virtualbox)
    doesn't bring up the virtual networking interface until a virtual machine is started.
    Cuckoo needs to have the interface where you bind the resultserver up before the start, so please
    check your network setup.

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

    # Specify the IP address of the current virtual machine. Make sure that the
    # IP address is valid and that the host machine is able to reach it. If not,
    # the analysis will fail.
    ip = 192.168.56.101

You can use this same configuration structure for any other machine manager module.

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


.. note::

    You may want to add a static IP address for your virtual machine::

        <network>
          ...
          <ip address="192.168.122.1" netmask="255.255.255.0">
            <dhcp>
              <range start="192.168.122.2" end="192.168.122.254" />
              <host mac="01:23:45:67:89:ab" ip="192.168.122.105" />
            </dhcp>
          </ip>
        </network>

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
    enabled = on

    [reporthtml]
    enabled = on

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
