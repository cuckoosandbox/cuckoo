=========
Utilities
=========

Cuckoo comes with a set of pre-built utilities to automate several common
tasks. Before these utilities could be found in the ``utils/`` directory but
since then we have moved to ``Cuckoo Apps``.

.. _cuckoo_apps:

Cuckoo Apps
===========

A ``Cuckoo App`` is essentially just a Cuckoo sub-command. There exist a
couple of Cuckoo Apps, each with their own functionality. It is important to
note that each Cuckoo App can be invoked in the same way. Following are some
examples::

    $ cuckoo submit --help
    $ cuckoo api --help
    $ cuckoo clean --help

In these examples we provided the ``--help`` parameter which shows the
functionality and all available parameters for the particular Cuckoo App.

Submission Utility
==================

Submits samples to analysis. This tool is described in :doc:`submit`.

Web Utility
===========

Cuckoo's web interface. This tool is described in :doc:`web`.

.. _cuckoo_process:

Processing Utility
==================

.. versionchanged:: 2.0.0
   We used to have longstanding issues with ``./utils/process.py`` randomly
   freezing up and ``./utils/process2.py`` only being able to handle
   PostgreSQL-based databases. These two commands have now been merged into
   one Cuckoo App and no longer show signs of said issues or limitations.

For bigger Cuckoo setups it is recommended to separate the results processing
from the Cuckoo analyses due to performance issues (with multiple threads &
the `Python GIL`_). Using ``cuckoo process`` it is also possible to
re-generate Cuckoo reports, this is mostly used while developing and debugging
Cuckoo Processing modules, Cuckoo Signatures, and Cuckoo Reporting modules.

In order to do results processing in one or more separate process(es) one has
to disable the ``process_results`` configuration item in
``$CWD/conf/cuckoo.conf`` by setting the value to ``off``. Then a Cuckoo
Processing instance has to be started, this can be done as follows::

    $ cuckoo process instance1

If one Cuckoo Processing instance is not enough to handle all the incoming
analyses, simply create a second, third, and possibly more instances::

    $ cuckoo process instance2

In order to re-generate a Cuckoo report of an analysis task, use the ``-r``
switch::

    $ cuckoo process -r 1

It is also possible to re-generate multiple or a range of Cuckoo reports at
once. The following will reprocess tasks ``1``, ``2``, ``5``, ``6``, ``7``,
``8``, ``9``, ``10``::

    $ cuckoo process -r 1,2,5-10

For more information see also the help on this ``Cuckoo App``::

    $ cuckoo process --help
    Usage: cuckoo process [OPTIONS] [INSTANCE]

      Process raw task data into reports.

    Options:
      -r, --report TEXT       Re-generate one or more reports
      -m, --maxcount INTEGER  Maximum number of analyses to process
      --help                  Show this message and exit.

In automated mode an instance name is required (e.g., ``instance1``) as seen
in the examples earlier above!

.. _`Python GIL`: https://wiki.python.org/moin/GlobalInterpreterLock

Community Download Utility
==========================

This ``Cuckoo App`` downloads Cuckoo Signatures, the latest monitoring
binaries, and other goodies from the `Cuckoo Community Repository`_ and
installs them in your ``CWD``.

To get all the latest and greatest from the Cuckoo Community simply execute
as follows and wait until it finishes - it currently doesn't have any progress
indication::

    $ cuckoo community

For more usage see as follows::

    $ cuckoo community --help
    Usage: cuckoo community [OPTIONS]

      Utility to fetch supplies from the Cuckoo Community.

    Options:
      -f, --force              Overwrite existing files
      -b, --branch TEXT        Specify a different community branch rather than
                               master
      --file, --filepath PATH  Specify a local copy of a community .tar.gz file
      --help                   Show this message and exit.

.. _`Cuckoo Community Repository`: https://github.com/cuckoosandbox/community

Database migration utility
==========================

.. versionchanged:: 2.0.0
   This used to be a special process, but has since been integrated properly
   as a Cuckoo App.

This utility helps migrating your data between Cuckoo releases. It's developed
on top of the `Alembic`_ framework and it should provide data migration for
both SQL database and Mongo database. This tool is already described
in :doc:`../installation/upgrade`.

.. _`Alembic`: http://alembic.readthedocs.org/en/latest/

Stats utility
=============

.. deprecated:: 2.0-rc2
    This utility will not be ported to a Cuckoo App as this information can
    also be retrieved through both the Cuckoo API as well as the Cuckoo Web
    Interface.

Machine utility
===============

.. versionchanged:: 2.0.0
   This used to be a standalone and hacky script directly modifying the Cuckoo
   configuration. It's now much better integrated and will be able to somewhat
   properly interact with Cuckoo.

The machine ``Cuckoo App`` is designed to help you automatize the
configuration of virtual machines in Cuckoo. It takes a list of machine
details as arguments and write them in the specified
configuration file of the machinery module enabled in *cuckoo.conf*.
Following are the available options::

    $ cuckoo machine --help
    Usage: cuckoo machine [OPTIONS] VMNAME [IP]

    Options:
      --debug              Enable verbose logging
      --add                Add a Virtual Machine
      --delete             Delete a Virtual Machine
      --platform TEXT      Guest Operating System
      --options TEXT       Machine options
      --tags TEXT          Tags for this Virtual Machine
      --interface TEXT     Sniffer interface for this Virtual Machine
      --snapshot TEXT      Specific Virtual Machine Snapshot to use
      --resultserver TEXT  IP:Port of the Result Server
      --help               Show this message and exit.

As an example, a machine may be added to Cuckoo's configuration as follows::

    $ cuckoo machine --add cuckoo1 192.168.56.101 --platform windows --snapshot vmcloak

Distributed scripts
===================

This tool is described in :doc:`dist`.

Mac OS X Bootstrap scripts
==========================

.. deprecated:: 2.0.0
    These files will be moved elsewhere in an upcoming update and so should
    any documentation that references these scripts.

A couple of bootstrap scripts used for Mac OS X analysis are located in
*utils/darwin* folder, they are used to bootstrap the guest and host system for
Mac OS X malware analysis.
Some settings are defined as constants inside them, so it is suggested to have a
look at them and configure them for your needs.

SMTP Sinkhole
=============

.. deprecated:: 2.0.0
    This script has been removed since this functionality should be
    implemented properly using a Postfix setup.

Setup script
============

.. deprecated:: 2.0.0
    This script has been replaced by a similar but much more powerful
    SaltStack state.
