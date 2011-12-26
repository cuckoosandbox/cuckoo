===========================
Cloning the Virtual Machine
===========================

In case you planned to use more than one virtual machine, there's no need to
repeat all the steps done so far: you can clone it. In this way you'll have
a copy of the original virtualized Windows with all requirements already
installed.

To clone a machine you can use the graphical user interface (at least in the
most recent versions of VirtualBox) or from the command line::

    $ VBoxManage clonevm "<Name of original VM>" --name "<Name of new VM>" --registervm

Now you have an exact copy of your original virtual machine saved with the new
name you specified.

Obviously the new virtual machine will bring along also the settings of the
original one, which is not good. Now you need to proceed repeating the steps
explained in :doc:`network`, :doc:`shares` and :doc:`saving` for this new
machine.

