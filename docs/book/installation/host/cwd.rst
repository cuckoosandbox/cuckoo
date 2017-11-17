.. _CWD:

========================
Cuckoo Working Directory
========================

.. versionadded:: 2.0.0

A new concept is the ``Cuckoo Working Directory``. From this point forward all
configurable components, generated data, and results of Cuckoo will be stored
in this directory. These files include but are not limited to the following:

* Configuration
* Cuckoo Signatures
* Cuckoo Analyzer
* Cuckoo Agent
* Yara rules
* Cuckoo Storage (where analysis results go)
* And much more..

The Cuckoo Working Directory comes with a couple of advantages over the legacy
approach that Cuckoo used. Following we will study how the
``Cuckoo Working Directory`` (``CWD`` from now on) overcomes various every-day
hurdles.

.. note:: This document merely shows the installation part of the ``CWD``, for
    its actual usage, please refer to the :doc:`../../usage/cwd` document.

Configuration
=============

If you have ever updated your Cuckoo setup to a later version, you have run
into the issue where you had to make a backup of your configuration, update
your Cuckoo instance, and either restore your configuration or re-apply it
completely.

With the introduction of the ``CWD`` we have gotten rid of this update
nightmare.

The first time you run ``Cuckoo`` a ``CWD`` checkout will be created for you
automatically, this pretty much goes as follows::

    $ cuckoo -d

            _       _                   _             _              _            _
            /\ \     /\_\               /\ \           /\_\           /\ \         /\ \
            /  \ \   / / /         _    /  \ \         / / /  _       /  \ \       /  \ \
            / /\ \ \  \ \ \__      /\_\ / /\ \ \       / / /  /\_\    / /\ \ \     / /\ \ \
        / / /\ \ \  \ \___\    / / // / /\ \ \     / / /__/ / /   / / /\ \ \   / / /\ \ \
        / / /  \ \_\  \__  /   / / // / /  \ \_\   / /\_____/ /   / / /  \ \_\ / / /  \ \_\
        / / /    \/_/  / / /   / / // / /    \/_/  / /\_______/   / / /   / / // / /   / / /
        / / /          / / /   / / // / /          / / /\ \ \     / / /   / / // / /   / / /
    / / /________  / / /___/ / // / /________  / / /  \ \ \   / / /___/ / // / /___/ / /
    / / /_________\/ / /____\/ // / /_________\/ / /    \ \ \ / / /____\/ // / /____\/ /
    \/____________/\/_________/ \/____________/\/_/      \_\_\\/_________/ \/_________/

    Cuckoo Sandbox 2.0.0
    www.cuckoosandbox.org
    Copyright (c) 2010-2017

    =======================================================================
        Welcome to Cuckoo Sandbox, this appears to be your first run!
        We will now set you up with our default configuration.
        You will be able to modify the configuration to your likings
        by exploring the /home/cuckoo/.cuckoo directory.

        Among other configurable things of most interest is the
        new location for your Cuckoo configuration:
                /home/cuckoo/.cuckoo/conf
    =======================================================================

    Cuckoo has finished setting up the default configuration.
    Please modify the default settings where required and
    start Cuckoo again (by running `cuckoo` or `cuckoo -d`).

As pointed out by the info messages you will now be able to find your ``CWD``
at ``/home/cuckoo/.cuckoo`` as it defaults to ``~/.cuckoo``. All configuration
files as you know them can be found in the ``$CWD/conf`` directory. I.e.,
``$CWD/conf/cuckoo.conf``, ``$CWD/conf/virtualbox.conf``, etc.

Now because the ``CWD`` directory is not part of Cuckoo itself, that is,
the Git repository or as part of one of the latest releases, one will be able
to upgrade Cuckoo without having to touch the ``CWD``. (Of course if an update
is installed that requires an updated Configuration then Cuckoo will guide the
user through it - instead of overwriting the Configuration files itself).

CWD path
========

Even though the ``CWD`` defaults to ``~/.cuckoo`` this path is completely
configurable. The following lists the order of precedence for Cuckoo to
determine the ``CWD``.

* Through the ``--cwd`` command-line option (e.g., ``--cwd ~/.cuckoo``).
* Through the ``CUCKOO`` environment variable (e.g., ``export CUCKOO=~/.cuckoo``).
* Through the ``CUCKOO_CWD`` environment variable.
* If the current directory is a ``CWD`` (e.g., ``cd ~/.cuckoo`` assuming that
  a ``CWD`` has been created in that directory).
* The default, ``~/.cuckoo``.

By using alternative ``CWD`` paths it is **possible to run multiple Cuckoo
instances with different configurations using the same Cuckoo setup**. If for
some reason one requires two or three separate Cuckoo setups, e.g., in the
case that you want to run Windows analysis and Android analysis in parallel,
then not having to upgrade each instance one-by-one every time there is an
update surely is a great step forward.

Following some examples to show how to configure the ``CWD``.

.. code-block:: bash

    # Places the CWD in /opt/cuckoo. Note that Cuckoo will normally create the
    # CWD itself, but in order to create a directory in /opt root capabilities
    # are usually required.
    $ sudo mkdir /opt/cuckoo
    $ sudo chown cuckoo:cuckoo /opt/cuckoo
    $ cuckoo --cwd /opt/cuckoo

    # You could place this line in your .bashrc, for example.
    $ export CUCKOO=/opt/cuckoo
    $ cuckoo

Experimenting with multiple Cuckoo setups is now as simple as creating
multiple ``CWD``'s and configuring them accordingly.
