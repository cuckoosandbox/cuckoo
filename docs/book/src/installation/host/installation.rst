=================
Installing Cuckoo
=================

Proceed with download and installation.

Create a user
=============

You either can run Cuckoo from your own user or create a new one dedicated just
to your sandbox setup.
Make sure that the user that runs Cuckoo is the same user that you will
use to create and run the virtual machines, otherwise Cuckoo won't be able to
identify and launch them.

Create a new user::

    $ sudo adduser cuckoo

If you're using VirtualBox, make sure the new user belongs to the "vboxusers"
group (or the group you used to run VirtualBox)::

    $ sudo useradd -G vboxusers cuckoo

If you're using KVM or any other libvirt based module, make sure the new user
belongs to the "libvirtd" group (or the group your Linux distribution uses to
run libvirt)::

	$ sudo useradd -G libvirtd cuckoo

Download Cuckoo
===============

You can get your copy of Cuckoo from the `official website`_ or from our
`git repository`_.

Please notice that the archives to be downloaded from the website are core
releases, while the version on git has to be considered an **under
development** stage, therefore possibly unstable and not yet fully documented.

.. _official website: http://www.cuckoosandbox.org
.. _git repository: https://github.com/cuckoobox/cuckoo

Install it
==========

Extract or checkout your copy of Cuckoo to a path of your choice and you're
ready to go ;-).

