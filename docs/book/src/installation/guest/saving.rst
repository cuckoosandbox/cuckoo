==========================
Saving the Virtual Machine
==========================

Now you should be ready to go and save the virtual machine to a snapshot state.

Before doing this make sure you rebooted it softly and that it's currently
running and with your Windows user logged in. Once you are sure that the
operating system is fully booted and ready to be snapshotted you can proceed.

You can take the snapshot from the graphical user interface or from the command
line::

    $ VBoxManage snapshot "<Name of VM>" take "<Name of snapshot>" --pause

After the snapshot creation is completed, you can power off the machine and
restore it::

    $ VBoxManage controlvm "<Name of VM>" poweroff
    $ VBoxManage snapshot "<Name of VM>" restorecurrent

If you followed all the steps properly, your virtual machine should be ready to
be used by Cuckoo.

