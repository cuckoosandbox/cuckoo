=================================
Upgrading from a previous release
=================================

Upgrading post version 2.0.0
============================

When updating your Cuckoo from a ``>=2.0.0`` version, Cuckoo will automatically
try to upgrade your :ref:`CWD` (CWD). If any actions are required, such as running automatically
database migrations or backing up an edited file in your CWD, Cuckoo will notify you.

To start an upgrade after updating Cuckoo, simply start Cuckoo as you normally would.

Upgrading to Cuckoo from legacy Cuckoo
======================================

Legacy Cuckoo is any Cuckoo version older than 2.0.0. These versions use a working directory
inside of the Cuckoo installation path. Newer Cuckoo versions use a :ref:`CWD`.

This document describes the process of *importing* an **older legacy Cuckoo setup** in
order to upgrade your Cuckoo to the latest and greatest version. This
importing process is possible for **Cuckoo 0.6 and upwards**. Naturally it
doesn't re-apply any **custom code changes** that you applied to your old
setup, but it does migrate your database, configuration, and analyses to the
new version (in a best-effort manner).

Now, in order to upgrade your setup, you'll simply have to perform the
following steps:

1. Come up with a :ref:`CWD` for the new setup (although the default one
   should work just fine, assuming it doesn't exist yet).
2. Optionally create a backup of your data (Cuckoo will also offer to do this
   for you before doing the actual setup import).
3. Run the ``cuckoo import`` command.

The cuckoo import command
=========================

The ``cuckoo import`` App performs a number of steps in order to import an
older setup. Previously we had manual steps for performing a database
migration, these have been integrated in the import process as well.


.. note:: Only use the import command if you are upgrading from a Cuckoo version pre 2.0.0.

The usage of ``cuckoo import`` is as follows::

    $ cuckoo import --help
    Usage: cuckoo import [OPTIONS] PATH

      Imports an older Cuckoo setup into a new CWD. The old setup should be
      identified by PATH and the new CWD may be specified with the --cwd
      parameter, e.g., "cuckoo --cwd /tmp/cwd import old-cuckoo".

    Options:
      --copy     Copy all existing analyses to the new CWD (default)
      --move     Move all existing analyses to the new CWD
      --symlink  Symlink all existing analyses to the new CWD
      --help  Show this message and exit.

As per the limited usage documentation of this command, there is an input and
an output directory and a couple of different *modes*. The rest is done by
``cuckoo import`` according to best-practice manners.

The three different modes are best described as follows. Keep in mind that
these modes only inform the importing process on what to do with the existing
analyses and, in the case of sqlite3 usage, the database file. These modes do
not apply to any other used databases or data not mentioned in this document.

* ``copy``: **Copies** all the analyses from the old setup to the new CWD. In
  this mode the old ``storage/`` folder will be copied to ``$CWD/storage/``.
  The ``copy`` mode is useful if you want to maintain a backup of the old
  setup and its analyses, allowing one to restore it with the appropriate SQL
  backup. *Note that this mode will double the size of your existing analyses
  directory as it does a full copy*.
* ``move``: **Moves** all the analyses from the old setup to the new CWD. In
  this mode the old ``storage/`` folder is moved to ``$CWD/storage/``. After
  the import process you won't have a backup of your old data anymore, but you
  will be able to reference to it in the new CWD / setup.
* ``symlink``: Creates a **symbolic link** from each analysis in the old
  setup, i.e., ``storage/analyses/XYZ``, to the new CWD, i.e.,
  ``$CWD/storage/XYZ``. This method is the most desired (as you'll be able to
  access the existing analyses in both the old setup as well as the new CWD),
  but doesn't work on Windows.

The default mode is ``copy`` due to its feature of remaining available on
both the old setup as well as the new CWD as well as being cross-platform
(i.e., ``symlink`` mode isn't supported on Windows). After reading this
documentation one may opt to go for ``symlink`` or ``move`` mode on
non-Windows systems and ``move`` mode on Windows systems, though.

Following are the steps taken by Cuckoo when performing an import:

* The user has to accept a non-binding EULA-like agreement that (just kidding)
  attempts to inform him or her regarding the implications of importing an
  older setup.
* The version of the old Cuckoo setup is identified.
* It is ensured that the new CWD does **not** already exist.
* The old Cuckoo Configuration is read, **migrated**, and then validated to be
  fit for usage with the new Cuckoo version, i.e., you can configure a Cuckoo
  0.6 setup and migrate it all the way to the latest version and it will
  simply work.
* The new CWD is created and it is configured with the migrated configuration.
* The user is prompted to *optionally* create a SQL database backup. On
  Linux-based systems this should work out of the box (and you'll get a hard
  error otherwise), but due to issues with ``$PATH`` this may require manually
  fixing up the command on Windows & Mac OS X systems.
* After the ability to create a SQL database backup, the **database schema**
  is **migrated** to the latest version **in-place**, i.e., you will not be
  able to use your old Cuckoo setup with this database anymore (hence the
  backup).
* Any and all existing analyses are imported to the new CWD using the ``mode``
  as specified, or if it has not been specified, the default ``copy`` method.

You are now the happy owner of an up-to-date Cuckoo setup. Please inform us of
any feedback that you may have through one of the various communication
channels that we've put in-place.

.. warning::
   One should **not** clean the old Cuckoo setup after the import. By
   attempting to do so you may lose the existing analyses (if ``symlink``
   mode is used) and the SQL, MongoDB, and ElasticSearch databases.
