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
    
     Cuckoo Sandbox 0.4
     www.cuckoobox.org
     Copyright (c) 2010-2012

    2012-06-11 20:17:29,694 [lib.cuckoo.core.scheduler] INFO: Loaded 1 machine/s
    2012-06-11 20:17:29,694 [lib.cuckoo.core.scheduler] INFO: Waiting for analysis tasks...

Now Cuckoo is ready to run and it's waiting for submissions.

``cuckoo.py`` accepts some command line options as shown by the help::

    usage: cuckoo.py [-h] [-q] [-d] [-v] [-l]

    optional arguments:
      -h, --help     show this help message and exit
      -q, --quiet    Display only error messages
      -d, --debug    Display debug messages
      -v, --version  show program's version number and exit
      -l, --logo     Show artwork

Most importantly ``--debug`` and ``--quiet`` respectively increase and decrease the logging
verbosity.