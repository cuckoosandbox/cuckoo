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

.. _install_cuckoo:

Install Cuckoo
==============

Installing the latest version of Cuckoo is as simple as follows. Note that it
is recommended to first upgrade the ``pip`` and ``setuptools`` libraries as
they're often outdated, leading to issues when trying to install Cuckoo (see
also :ref:`pip_install_issue`).

.. warning::
   It is not unlikely that you'll be missing one or more system packages
   required to build various Python dependencies. Please read and re-read
   :doc:`requirements` to resolve these sorts of issues.

.. code-block:: bash

    $ sudo pip install -U pip setuptools
    $ sudo pip install -U cuckoo

Although the above, a *global* installation of Cuckoo in your OS works mostly
fine, we **highly recommend** installing Cuckoo in a ``virtualenv``, which
looks roughly as follows::

    $ virtualenv venv
    $ . venv/bin/activate
    (venv)$ pip install -U pip setuptools
    (venv)$ pip install -U cuckoo

.. note::
    Depending on how you have set up your environment (virtualenvs etc.) you
    may need to specify the version of ``pip`` to use. Just replace ``pip``
    in the commands above with ``pip2``.

Some reasons for using a ``virtualenv``:

* Cuckoo's dependencies may not be entirely up-to-date, but instead pin to a
  known-to-work-properly version.
* The dependencies of other software installed on your system may conflict
  with those required by Cuckoo, due to incompatible version requirements (and
  yes, this is also possible when Cuckoo supports the latest version, simply
  because the other software may have pinned to an older version).
* Using a virtualenv allows non-root users to install additional packages or
  upgrade Cuckoo at a later point in time.
* And simply put, virtualenv is considered a best practice.

Please refer to :doc:`cwd` and :doc:`../../usage/cwd` to learn more about the
``Cuckoo Working Directory`` and how to operate it.

Install Cuckoo from file
========================

By downloading a hard copy of the Cuckoo Package and installing it *offline*,
one may set up Cuckoo using a cached copy and/or have a backup copy of current
Cuckoo versions in the future. We also feature the option to download such a
tarball on our website.

Obtaining the tarball of Cuckoo and all of its dependencies manually may be
done as follows::

    $ pip download cuckoo

You will end up with a file ``Cuckoo-2.0.0.tar.gz`` (or a higher number,
depending on the latest released stable version) as well as all of its
dependencies (e.g., ``alembic-0.8.8.tar.gz``).

Installing that exact version of Cuckoo may be done as you're familiar with
from installing it using ``pip`` directly, except now using the filename of
the tarball::

    $ pip install Cuckoo-2.0.0.tar.gz

On systems where no internet connection is available, the ``$ pip download
cuckoo`` command may be used to fetch all of the required dependencies and as
such one should be able to - in theory - install Cuckoo completely offline
using those files, i.e., by executing something like the following::

    $ pip install *.tar.gz

Build/Install Cuckoo from source
================================

By cloning Cuckoo Sandbox from our `official repository`_, you can install it from source.
After cloning, follow the steps mentioned in :doc:`../../development/package` to start the installation.

.. _`official repository`: https://github.com/cuckoosandbox/cuckoo
