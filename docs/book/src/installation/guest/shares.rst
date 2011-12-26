==============
Shared Folders
==============

Cuckoo exchanges data between the host and the guest using VirtualBox's Shared
Folders.

In order to have them enabled on your virtual machine you should have installed
the Guest Additions as specified in :doc:`requirements`.

You will have to add two shared folders:

    * **shares/setup**: which is used to get Cuckoo analyzer's components to be run inside virtualized Windows.
    * **shares/<VM ID>**: the unique shared folder associated with your current Virtual Machine, which is used to store the analysis results.

You can do so from VirtualBox's graphical user interface or from the command line::

    $ VBoxManage sharedfolder add "<Name of VM>" --name "setup" --hostpath "/path/to/cuckoo/shares/setup" --readonly
    $ VBoxManage sharedfolder add "<Name of VM>" --name "<VM ID>" --hostpath "/path/to/cuckoo/shares/<VM ID>"

Where "*<Name of VM>*" is the label you gave to the virtual machine in VirtualBox
and "*<VM ID>*" is the ID you assigned to the Virtual Machine in Cuckoo.

Using the GUI, you should see something similar to this:

    .. figure:: ../../_images/screenshots/shared_folders.png
        :align: center

