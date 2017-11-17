===============================
Creation of the Virtual Machine
===============================

Once you have :doc:`properly installed <../host/requirements>` your
virtualization software, you can proceed on creating all the virtual machines
you need.

Using and configuring your virtualization software is out of the scope of this
guide, so please refer to the official documentation.

.. note::

    You can find some hints and considerations on how to design and create
    your virtualized environment in the :doc:`../../introduction/sandboxing`
    chapter.

.. note::

    We recommend either 64-bit Windows 7 or Windows XP virtual machines.
    For Windows 7 you will have to disable User Access Control.

    .. versionchanged:: 2.0-rc2
       We used to suggest Windows XP as a guest VM but nowadays a 64-bit
       Windows 7 machine yields much better results.

.. note::

    KVM Users - Be sure to choose a hard drive image format that supports snapshots.
    See :doc:`saving`
    for more information.

When creating the virtual machine, Cuckoo doesn't require any specific
configuration. You can choose the options that best fit your needs.
