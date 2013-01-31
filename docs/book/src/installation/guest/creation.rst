===============================
Creation of the Virtual Machine
===============================

Once you have :doc:`properly installed <../host/requirements>` your virtualization
software, you can proceed on creating all the virtual machines you need.

Using and configuring your virtualization software is out of the scope of this
guide, so please refer to the official documentation.

    .. note::

        You can find some hints and considerations on how to design and create
        your virtualized environment in the :doc:`../../introduction/sandboxing`
        chapter.

    .. note::

        For analysis purposes you are recommended to use Windows XP Service Pack
        3, but Cuckoo Sandbox also proved to work with Windows 7 with User
        Access Control disabled.

    .. note::

        KVM Users - Be sure to choose a hard drive image format that supports snapshots.
        See :doc:`../../Installation/Preparing the Guest/Saving the Virtual Machine/KVM`
        for more information.

When creating the virtual machine, Cuckoo doesn't require any specific
configuration. You can choose the options that best fit your needs.
