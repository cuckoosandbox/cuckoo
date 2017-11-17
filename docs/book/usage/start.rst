===============
Starting Cuckoo
===============

To start Cuckoo use the command::

    $ cuckoo

You will get an output similar to this::

      eeee e   e eeee e   e  eeeee eeeee
      8  8 8   8 8  8 8   8  8  88 8  88
      8e   8e  8 8e   8eee8e 8   8 8   8
      88   88  8 88   88   8 8   8 8   8
      88e8 88ee8 88e8 88   8 8eee8 8eee8

     Cuckoo Sandbox 2.0.0
     www.cuckoosandbox.org
     Copyright (c) 2010-2017

     Checking for updates...
     Good! You have the latest version available.

    2017-03-31 17:08:53,527 [cuckoo.core.scheduler] INFO: Using "virtualbox" as machine manager
    2017-03-31 17:08:53,935 [cuckoo.core.scheduler] INFO: Loaded 1 machine/s
    2017-03-31 17:08:53,964 [cuckoo.core.scheduler] INFO: Waiting for analysis tasks.


Note that Cuckoo checks for updates on a remote API located at
``api.cuckoosandbox.org``. You can avoid this by disabling the
``version_check`` option in the configuration file.

Now Cuckoo is ready to run and it's waiting for submissions.

``cuckoo`` accepts some command line options as shown by the help::

    $ cuckoo --help
    Usage: cuckoo [OPTIONS] COMMAND [ARGS]...

    Invokes the Cuckoo daemon or one of its subcommands.

    To be able to use different Cuckoo configurations on the same
    machine with the same Cuckoo installation, we use the so-called
    Cuckoo Working Directory (aka "CWD"). A default CWD is
    available, but may be overridden through the following options -
    listed in order of precedence.

    * Command-line option (--cwd)
    * Environment option ("CUCKOO")
    * Environment option ("CUCKOO_CWD")
    * Current directory (if the ".cwd" file exists)
    * Default value ("~/.cuckoo")

    Options:
      -d, --debug             Enable verbose logging
      -q, --quiet             Only log warnings and critical messages
      -m, --maxcount INTEGER  Maximum number of analyses to process
      --user TEXT             Drop privileges to this user
      --cwd TEXT              Cuckoo Working Directory
      --help                  Show this message and exit.

    Commands:
      api          Operate the Cuckoo REST API.
      clean        Clean the CWD and associated databases.
      community    Fetch supplies from the Cuckoo Community.
      distributed  Distributed Cuckoo helper utilities.
      dnsserve     Custom DNS server.
      import       Imports an older Cuckoo setup into a new CWD.
      init         Initializes Cuckoo and its configuration.
      machine      Dynamically add/remove machines.
      migrate      Perform database migrations.
      process      Process raw task data into reports.
      rooter       Instantiates the Cuckoo Rooter.
      submit       Submit one or more files or URLs to Cuckoo.
      web          Operate the Cuckoo Web Interface.

The ``--debug`` and ``--quiet`` flags increase and decrease the logging
verbosity for the ``cuckoo`` command or any of its subcommands.

.. _cuckoo_background:

Cuckoo in the background
========================

Running Cuckoo manually is useful the first few times you start using it, but
if you're running multiple machines with Cuckoo on it, you will want the
process of running Cuckoo to be automated.

Fortunately Cuckoo will automatically provide one with a ``supervisord.conf``
file in the ``Cuckoo Working Directory`` (this topic will be explained on the
next page) which may be started either by running ``supervisord`` from the
``CWD`` directory, or by providing the configuration directly to
``supervisord`` as follows::

    $ supervisord -c $CWD/supervisord.conf

It should be noted that, by default, ``supervisord`` will also start four
:ref:`cuckoo_process` instances, which means that, as per its documentation,
the ``process_results`` configuration in ``$CWD/conf/cuckoo.conf`` should be
disabled (i.e., change the value from ``on`` to ``off``).

From there on, one may start and stop the various cuckoo processes (i.e., the
main cuckoo process and the four processing instances) by running commands
such as the following (assuming that they're run from the ``CWD``)::

    # Stop the Cuckoo daemon and the processing utilities.
    $ supervisorctl stop cuckoo:

    # Start the Cuckoo daemon and the processing utilities.
    $ supervisorctl start cuckoo:

Note that you'll need the trailing colon (i.e., ``cuckoo:``) so to denote the
Cuckoo supervisor ``group``, containing the Cuckoo daemon process as well as
the various processing utilities.
