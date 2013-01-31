==========================
Saving the Virtual Machine
==========================

Now you should be ready to go and save the virtual machine to a snapshot state.

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

If decided to adopt KVM, you must fist of all be sure to use a disk format for 
your virtual machines which supports snapshots.
By default libvirt tools create RAW virtual disks, and since we need snapshots
you'll either have to use QCOW2 or LVM. For the scope of this guide we adopt QCOW2,
which is easier to setup than LVM.

The easiest way to create such a virtual disk in the correct way is using the
tools provided by the libvirt suite. You can either use ``virsh`` if you prefer
command-line interfaces or ``virt-manager`` for a nice GUI.
You should be able to directly create it in QCOW2 format, but in case you have
a RAW disk you can convert it like following::

    $ cd /your/disk/image/path
    $ qemu-img convert -O qcow2 your_disk.raw your_disk.qcow2

Now you have to edit your VM definition like following::

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

Now test your virtual machine, if all works prepare it for snapshotting while
running Cuckoo's agent. This means the virtual machine needs to be running
while you are taking the snapshot. Then you can shut it down.
You can finally take a snapshot with the following command::

    $ virsh snapshot-create "<Name of VM>"

Having multiple snapshots can cause errors.

ERROR: No snapshot found for virtual machine VM-Name

VM snapshots can be managed using the following commands.

    $ virsh snapshot-list "VM-Name"

    $ virsh snapshot-delete "VM-Name" 1234567890

VMware Workstation
==================

If decided to adopt VMware Workstation, you can take the snapshot from the graphical user
interface or from the command line::

    $ vmrun snapshot "/your/disk/image/path/wmware_image_name.vmx" your_snapshot_name

Where your_snapshot_name is the name you choose for the snapshot.
After that power off the machine from the graphical user interface or from the
command line::

    $ vmrun stop "/your/disk/image/path/wmware_image_name.vmx" hard
