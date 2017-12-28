.. _rooter:

=============
Cuckoo Rooter
=============

The ``Cuckoo Rooter`` is a new concept, providing ``root`` access for various
commands to Cuckoo (which itself generally speaking runs as non-root). This
command is currently only available for Ubuntu and Debian-like systems.

In particular, the ``rooter`` helps Cuckoo out with running network-related
commands in order to provide **per-analysis routing** options. For more
information on that, please refer to the :ref:`routing` document. Cuckoo and
the ``rooter`` communicate through a UNIX socket for which the ``rooter``
makes sure that Cuckoo can reach it.

Its usage is as follows::

    $ cuckoo rooter --help
    Usage: cuckoo rooter [OPTIONS] [SOCKET]

    Options:
      -g, --group TEXT  Unix socket group
      --service PATH    Path to service(8) for invoking OpenVPN
      --iptables PATH   Path to iptables(8)
      --ip PATH         Path to ip(8)
      --sudo            Request superuser privileges
      --help            Show this message and exit.

By default the ``rooter`` will default to ``chown``'ing the ``cuckoo`` user as
user and group for the UNIX socket, as recommended when :ref:`installing`.
If you're running Cuckoo under a user other than ``cuckoo``, you will have to
specify this to the ``rooter`` as follows::

    $ sudo cuckoo rooter -g <user>

The other options are fairly straightforward - you can specify the paths to
specific Linux commands. By default one shouldn't have to do this though, as
the ``rooter`` takes the default paths for the various utilities as per a
default setup.

Virtualenv
==========

Due to the fact that the ``rooter`` must be run as ``root`` user, there are
some slight complications when using a ``virtualenv`` to run Cuckoo. More
specifically, when running ``sudo cuckoo rooter``, the ``$VIRTUAL_ENV``
environment variable will not be passed along, due to which Python will not be
executed from the same ``virtualenv`` as it would have been normally.

To resolve this one simply has to execute the ``cuckoo`` binary from the
``virtualenv`` session directly. E.g., if your ``virtualenv`` is located at
``~/venv``, then running the ``rooter`` command could be done as follows::

    $ sudo ~/venv/bin/cuckoo rooter

Alternatively one may use the ``--sudo`` flag which will call ``sudo`` on the
correct ``cuckoo`` binary with all the provided flags. In turn the user will
have to enter his or her password and, assuming all is fine, the Cuckoo Rooter
will be started properly, e.g.::

    (venv)$ cuckoo rooter --sudo

.. _cuckoo_rooter_usage:

Cuckoo Rooter Usage
===================

Using the ``Cuckoo Rooter`` is actually pretty easy. If you know how to start
it, you're basically good to go. Even though Cuckoo talks with the Cuckoo
Rooter for each analysis with a routing option other than :ref:`routing_none`,
the Cuckoo Rooter does not keep any state or attach to any Cuckoo instance in
particular.

It is therefore that once the Cuckoo Rooter has been started you may leave it
be - the Cuckoo Rooter will take care of itself from that point onwards, no
matter how often you restart your Cuckoo instance.
