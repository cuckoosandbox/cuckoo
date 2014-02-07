===============
Starting Cuckoo
===============

To start Cuckoo use the command::

    $ python cuckoo.py

Make sure to run it inside Cuckoo's root directory.

You will get an output similar to this::

      eeee e   e eeee e   e  eeeee eeeee 
      8  8 8   8 8  8 8   8  8  88 8  88 
      8e   8e  8 8e   8eee8e 8   8 8   8 
      88   88  8 88   88   8 8   8 8   8 
      88e8 88ee8 88e8 88   8 8eee8 8eee8

     Cuckoo Sandbox 1.0
     www.cuckoosandbox.org
     Copyright (c) 2010-2014

     Checking for updates...
     Good! You have the latest version available.

    2013-04-07 15:57:17,459 [lib.cuckoo.core.scheduler] INFO: Using "virtualbox" machine manager
    2013-04-07 15:57:17,861 [lib.cuckoo.core.scheduler] INFO: Loaded 1 machine/s
    2013-04-07 15:57:17,862 [lib.cuckoo.core.scheduler] INFO: Waiting for analysis tasks...

Note that Cuckoo checks for updates on a remote API located at *api.cuckoosandbox.org*.
You can avoid this by disabling the ``version_check`` option in the configuration file.

Now Cuckoo is ready to run and it's waiting for submissions.

``cuckoo.py`` accepts some command line options as shown by the help::

    usage: cuckoo.py [-h] [-q] [-d] [-v] [-a]

    optional arguments:
      -h, --help     show this help message and exit
      -q, --quiet    Display only error messages
      -d, --debug    Display debug messages
      -v, --version  show program's version number and exit
      -a, --artwork  Show artwork

Most importantly ``--debug`` and ``--quiet`` respectively increase and decrease the logging
verbosity.
