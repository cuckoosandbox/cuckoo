================
Machine Managers
================

**Machine managers** are modules that define how Cuckoo should interact with
your virtualization software (or potentially even with physical disk imaging
solutions).
Since we decided to not enforce any particular vendor, from release 0.4 you
are able to use your preferred and, in case is not supported by default,
write a custom Python module that define how to make Cuckoo use it.

Every machine manager module is and should be located inside 
*modules/machinemanagers/*.

A basic machine manager could look like:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import MachineManager
        from lib.cuckoo.common.exceptions import CuckooMachineError

        class MyManager(MachineManager):
            def start(self, label):
                try:
                    revert(label)
                    start(label)
                except SomethingBadHappens as e:
                    raise CuckooMachineError("OPS!")

            def stop(self, label):
                try:
                    stop(label)
                except SomethingBadHappens as e:
                    raise CuckooMachineError("OPS!")

The only requirements for Cuckoo are that:

    * The class inherits ``MachineManager``.
    * You have a ``start()`` and ``stop()`` functions.
    * You preferably raise ``CuckooMachineError`` when something fails.

As you understand, the machine manager is a core part of a Cuckoo setup,
therefore make sure to spend enough time debugging your code and make it
solid and resistant to any unexpected error.

Configuration
=============

Every machine manager module should come with a dedicated configuration file
located in *conf/<machine manager name>.conf*.
For example for *modules/machinemanagers/kvm.py* we have a *conf/kvm.conf*.

The configuration file should follow the default structure::

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

    # Specify the IP address of the current machine. Make sure that the IP address
    # is valid and that the host machine is able to reach it. If not, the analysis
    # will fail.
    ip = 192.168.122.105

A main section called ``[<name of the module>]`` with a ``machines`` field
containing a comma-separated list of machines IDs.

For each machine you should specify a ``label``, a ``platform`` and it's
``ip``.

These fields are required by Cuckoo in order to use the already embedded ``initialize()``
function that generates the list of available machines.

If you plan to change the configuration structure you should override the ``initialize()``
function (inside your own module, no need to modify Cuckoo's core code).
You can find it's original code in the ``MachineManager`` abstract inside
*lib/cuckoo/common/abstracts.py*.

LibVirt
=======

Starting with Cuckoo 0.5 developing new machine managers based on LibVirt is easy.
Inside *lib/cuckoo/common/abstracts.py* you can find ``LibVirtMachineManager`` that
already provides all the functionalities for a LibVirt machine manager.
Just inherit this base class and specify your connection string, as in
the example below:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import LibVirtMachineManager

		class MyMachineManager(LibVirtMachineManager):
		    # Set connection string.
		    dsn = "my:///connection"


This works for all the virtualization technologies supported by LibVirt. Just remember to 
check if your LibVirt package (if you are using one, for example from your Linux
distribution) is compiled with the support for the technology you need.

You can check it with the following command::

	$ virsh -V
	Virsh command line tool of libvirt 0.9.13
	See web site at http://libvirt.org/
	
	Compiled with support for:
	 Hypervisors: QEmu/KVM LXC UML Xen OpenVZ VMWare Test
	 Networking: Remote Daemon Network Bridging Interface Nwfilter VirtualPort
	 Storage: Dir Disk Filesystem SCSI Multipath iSCSI LVM
	 Miscellaneous: Nodedev AppArmor Secrets Debug Readline Modular

If you don't find your virtualization technology in the list of ``Hypervisors``, you will
need to recompile LibVirt with the specific support for the missing one.
