===============
Starting Cuckoo
===============

To start Cuckoo use the command::

    $ python cuckoo.py

Make sure to run it inside Cuckoo's root directory.

You will get an output similar to this::

                              .:                 
                              ::                 
        .-.     ,  :   .-.    ;;.-.  .-.   .-.   
       ;       ;   ;  ;       ;; .' ;   ;';   ;' 
       `;;;;'.'`..:;._`;;;;'_.'`  `.`;;'  `;;'
    
     Cuckoo Sandbox 0.5
     www.cuckoosandbox.org
     Copyright (c) 2010-2012

     Checking for updates...
     Good! You have the latest version available.

    2012-12-18 14:56:31,036 [lib.cuckoo.core.scheduler] INFO: Using "virtualbox" machine manager
    2012-12-18 14:56:31,861 [lib.cuckoo.core.scheduler] INFO: Loaded 1 machine/s
    2012-12-18 14:56:31,862 [lib.cuckoo.core.scheduler] INFO: Waiting for analysis tasks...

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