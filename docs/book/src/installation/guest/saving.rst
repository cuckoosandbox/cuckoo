==========================
Saving the Virtual Machine
==========================

Now you should be ready to go and save the virtual machine to a snapshot state.

Before doing this **make sure you rebooted it softly and that it's currently
running and with Windows fully booted**. 

Now you can proceed saving the machine. The way to do it obviously depends on
the virtualization software you decided to use, but if for example you are
going for VirtualBox you can take the snapshot from the graphical user 
interface or from the command line::

    $ VBoxManage snapshot "<Name of VM>" take "<Name of snapshot>" --pause

After the snapshot creation is completed, you can power off the machine and
restore it::

    $ VBoxManage controlvm "<Name of VM>" poweroff
    $ VBoxManage snapshot "<Name of VM"> restorecurrent

If you followed all the steps properly, your virtual machine should be ready to
be used by Cuckoo.

