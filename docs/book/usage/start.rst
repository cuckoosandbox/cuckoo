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

     Cuckoo Sandbox 2.0-rc2
     www.cuckoosandbox.org
     Copyright (c) 2010-2016

     Checking for updates...
     Good! You have the latest version available.

    2013-04-07 15:57:17,459 [lib.cuckoo.core.scheduler] INFO: Using "virtualbox" machine manager
    2013-04-07 15:57:17,861 [lib.cuckoo.core.scheduler] INFO: Loaded 1 machine/s
    2013-04-07 15:57:17,862 [lib.cuckoo.core.scheduler] INFO: Waiting for analysis tasks...

Note that Cuckoo checks for updates on a remote API located at ``api.cuckoosandbox.org``.
You can avoid this by disabling the ``version_check`` option in the configuration file.

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
      api
      clean        Utility to clean the Cuckoo Working Directory...
      community    Utility to fetch supplies from the Cuckoo...
      distributed
      dnsserve
      machine
      migrate
      process      Process raw task data into reports.
      rooter
      submit       Submit one or more files or URLs to Cuckoo.
      web          Starts the Cuckoo Web Interface or dumps its...

The ``--debug`` and ``--quiet`` flags increase and decrease the logging
verbosity for the ``cuckoo`` command or any of its subcommands.
