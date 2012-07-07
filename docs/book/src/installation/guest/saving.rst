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

If you are going for KVM, first of all, you must be sure to use a disk format for 
your virtual machines which supports snapshots.
By default libvirt tools create virtual machine with default disk format RAW, we
need to use snapshots so the disk format must support it, you can choose for 
QCOW2 or LVM format. For the scope of this guide we show an example with QCOW2,
which is easier to setup than LVM.

The easy way to create a virtual machine which supports snapshots, if you don't
know how to do it from scratch, is to create a KVM machine with RAW disk using
the libvirt creation tools (we suggest virsh if you like line interfaces or 
virt-manager if you like graphical interfaces), after the creation you can covert
the disk to QCOW2 with the following command::

	$ cd /your/disk/image/path
	$ qemu-img convert -O qcow2 your_disk.raw your_disk.qcow2

Now you have to edit your VM definition, use the following command to edit the
virtual machine XML::

	$ virsh edit machine_name

Search the disk section, it looks like this::

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

Now test your virtual machine, if all works prepare it for snapshotting running
Cuckoo agent.
Take a snapshot with the following command::

	$ virsh snapshot-create machine_name
