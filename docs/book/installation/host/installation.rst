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

Raising file limits
===================

As outlined in the :doc:`../../faq/index` entry :ref:`openfiles24` one may
want to bump the file count limits before starting Cuckoo as otherwise some
samples will fail to properly process the report (due to opening more files
than allowed by the Operating System).

Install Cuckoo
==============

Installing the latest version of Cuckoo is as simple as follows. Note that it
is recommended to first upgrade the ``pip`` and ``setuptools`` libraries as
they're often outdated, leading to issues when trying to install Cuckoo (see
also :ref:`pip_install_issue`).

.. code-block:: bash

    $ sudo pip install -U pip setuptools
    $ sudo pip install -U cuckoo

Or, when using ``virtualenv``, something similar to the following::

    (venv)$ pip install -U pip setuptools
    (venv)$ pip install -U cuckoo

Please refer to :doc:`cwd` and :doc:`../../usage/cwd` to learn more about the
``Cuckoo Working Directory`` and how to operate it.
