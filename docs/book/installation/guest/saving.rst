==========================
Saving the Virtual Machine
==========================

Now you should be ready to save the virtual machine to a snapshot state.

Before doing this **make sure you rebooted it softly and that it's currently
running, with Cuckoo's agent running and with Windows fully booted**.

Now you can proceed saving the machine. The way to do it obviously depends on
the virtualization software you decided to use.

If you follow all the below steps properly, your virtual machine should be ready
to be used by Cuckoo.

VirtualBox
==========

If you are going for VirtualBox you can take the snapshot from the graphical user
interface or from the command line::

    $ VBoxManage snapshot "<Name of VM>" take "<Name of snapshot>" --pause

After the snapshot creation is completed, you can power off the machine and
restore it::

    $ VBoxManage controlvm "<Name of VM>" poweroff
    $ VBoxManage snapshot "<Name of VM>" restorecurrent

KVM
===

If decided to adopt KVM, you must first of all be sure to use a disk format for
your virtual machines which supports snapshots.
By default libvirt tools create RAW virtual disks, and since we need snapshots
you'll either have to use QCOW2 or LVM. For the scope of this guide we adopt QCOW2,
which is easier to setup than LVM.

The easiest way to create such a virtual disk correctly is using the tools
provided by the libvirt suite. You can either use ``virsh`` if you prefer
command-line interfaces or ``virt-manager`` for a nice GUI.
You should be able to directly create it in QCOW2 format, but in case you have
a RAW disk you can convert it like this::

    $ cd /your/disk/image/path
    $ qemu-img convert -O qcow2 your_disk.raw your_disk.qcow2

Now you have to edit your VM definition as follows::

    $ virsh edit "<Name of VM>"

Find the disk section, it looks like this::

    <disk type='file' device='disk'>
        <driver name='qemu' type='raw'/>
        <source file='/your/disk/image/path/your_disk.raw'/>
        <target dev='hda' bus='ide'/>
        <address type='drive' controller='0' bus='0' unit='0'/>
    </disk>

And change "type" to qcow2 and "source file" to your qcow2 disk image, like this::

    <disk type='file' device='disk'>
        <driver name='qemu' type='qcow2'/>
        <source file='/your/disk/image/path/your_disk.qcow2'/>
        <target dev='hda' bus='ide'/>
        <address type='drive' controller='0' bus='0' unit='0'/>
    </disk>

Now test your virtual machine, if everything works prepare it for snapshotting while
running Cuckoo's agent. This means the virtual machine needs to be running
while you are taking the snapshot. Then you can shut it down.
You can finally take a snapshot with the following command::

    $ virsh snapshot-create "<Name of VM>"

Having multiple snapshots can cause errors::

    ERROR: No snapshot found for virtual machine VM-Name

VM snapshots can be managed using the following commands::

    $ virsh snapshot-list "VM-Name"
    $ virsh snapshot-delete "VM-Name" 1234567890

VMware Workstation
==================

If you decided to adopt VMware Workstation, you can take the snapshot from the graphical user
interface or from the command line::

    $ vmrun snapshot "/your/disk/image/path/wmware_image_name.vmx" your_snapshot_name

Where your_snapshot_name is the name you choose for the snapshot.
After that power off the machine from the GUI or from the command line::

    $ vmrun stop "/your/disk/image/path/wmware_image_name.vmx" hard

XenServer
=========

If you decided to adopt XenServer, the XenServer machinery supports starting
virtual machines from either disk or a memory snapshot. Creating and reverting
memory snapshots require that the Xen guest tools be installed in the
virtual machine. The recommended method of booting XenServer virtual machines is
through memory snapshots because they can greatly reduce the boot time of
virtual machines during analysis. If, however, the option of installing the
guest tools is not available, the virtual machine can be configured to have its
disks reset on boot. Resetting the disk ensures that malware samples cannot
permanently modify the virtual machine.

Memory Snapshots
----------------

The Xen guest tools can be installed from the XenCenter application that ships
with XenServer. Once installed, restart the virtual machine and ensure that the
Cuckoo agent is running.

Snapshots can be taken through the XenCenter application and the command line
interface on the control domain (Dom0). When creating the snapshot from
XenCenter, ensure that the "Snapshot disk and memory" is checked. Once created,
right-click on the snapshot and note the snapshot UUID.

To snapshot from the command line interface, run the following command::

    $ xe vm-checkpoint vm="vm_uuid_or_name" new-name-label="Snapshot Name/Description"

The snapshot UUID is printed to the screen once the command completes.

Regardless of how the snapshot was created, save the UUID in the virtual
machine's configuration section. Once the snapshot has been created, you can
shutdown the virtual machine.

Booting from Disk
-----------------

If you can't install the Xen guest tools or if you don't need to use memory
snapshots, you will need to ensure that the virtual machine's disks are reset on
boot and that the Cuckoo agent is set to run at boot time.

Running the agent at boot time can be configured in Windows by adding a startup
item for the agent.

The following commands must be run while the virtual machine is powered off.

To set the virtual machine's disks to reset on boot, you'll first need to list
all the attached disks for the virtual machine. To list all attached disks, run
the following command::

    $ xe vm-disk-list vm="vm_name_or_uuid"

Ignoring all CD-ROM and read-only disks, run the following command for each
remaining disk to change it's behavior to reset on boot::

    $ xe vdi-param-set uuid="vdi_uuid" on-boot=reset

After the disk is set to reset on boot, no permanent changes can be made to the
virtual machine's disk. Modifications that occur while a virtual machine is
running will not persist past shutdown.
