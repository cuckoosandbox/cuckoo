.. _installing:

=================
Installing Cuckoo
=================

Create a user
=============

You can either run Cuckoo from your own user or create a new one dedicated
just for your sandbox setup. Make sure that the user that runs Cuckoo is the
same user that you will use to create and run the virtual machines (at least
in the case of VirtualBox), otherwise Cuckoo won't be able to identify and
launch these Virtual Machines.

Create a new user::

    $ sudo adduser cuckoo

If you're using VirtualBox, make sure the new user belongs to the "vboxusers"
group (or the group you used to run VirtualBox)::

    $ sudo usermod -a -G vboxusers cuckoo

If you're using KVM or any other libvirt based module, make sure the new user
belongs to the "libvirtd" group (or the group your Linux distribution uses to
run libvirt)::

    $ sudo usermod -a -G libvirtd cuckoo

Install Cuckoo
==============

Installing the latest version of Cuckoo is as simple as follows::

    $ sudo pip install -U cuckoo

Or, when using ``virtualenv``, something similar to the following::

    (venv) $ pip install -U cuckoo

Please refer to :doc:`cwd` and :doc:`../../usage/cwd` to learn more about the
``Cuckoo Working Directory`` and how to operate it.
