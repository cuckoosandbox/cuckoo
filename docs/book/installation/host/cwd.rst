========================
Cuckoo Working Directory
========================

.. versionadded:: 2.0-rc2

A new concept is the ``Cuckoo Working Directory``. From this point forward all
configurable components, generated data, and results of Cuckoo will be stored
in this directory. These files include but are not limited to the following:

    * **Configuration**
    * Cuckoo Signatures
    * The Analyzer
    * The Agent
    * Yara rules
    * Cuckoo Storage (where analysis results go)

The Cuckoo Working Directory comes with a couple of advantages over the legacy
approach that Cuckoo used. Following we will study how the
``Cuckoo Working Directory`` (``CWD`` from now on) overcomes some every-day
hurdles.

Configuration
=============

If you have ever updated your Cuckoo setup to the latest version, you have run
into the issue where you had to make a backup of your configuration, update
your Cuckoo instance, and either restore your configuration or re-apply it
completely.

With the introduction of the ``CWD`` we have gotten rid of this update
nightmare.

The first time you run ``Cuckoo`` a ``CWD`` checkout will be created for you
automatically, this pretty much goes as follows::

    $ cuckoo

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

    Cuckoo Sandbox 2.0-dev
    www.cuckoosandbox.org
    Copyright (c) 2010-2016

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

CWD Path
========

Even though the ``CWD`` defaults to ``~/.cuckoo`` this path is completely
configurable. It can be modified globally through the ``CUCKOO`` environment
variable or passed along to a command whenever an alternative ``CWD`` is
required.

By using alternative ``CWD`` paths it is **possible to run multiple Cuckoo
instances with different configurations but using the same Cuckoo setup**.
If for some reason one requires two or three separate Cuckoo setups, e.g., in
the case that you want to run Windows analysis and Android analysis in
parallel, then not having to upgrade each instance one-by-one every time there
is an update surely is a good step forward.

Following some examples to show how to configure the ``CWD``::

    # Places the CWD in /opt/cuckoo. Note that Cuckoo will normally create the
    # CWD itself, but in order to create a directory in /opt root capabilities
    # are usually required.
    $ sudo mkdir /opt/cuckoo
    $ sudo chown cuckoo:cuckoo /opt/cuckoo
    $ cuckoo --cwd /opt/cuckoo

    # You could place this line in your .bashrc, for example.
    $ export CUCKOO=~/cuckoo-cwd
    $ cuckoo

Experimenting with multiple Cuckoo setups is now as simple as creating
multiple ``CWD``'s and configuring them accordingly.
