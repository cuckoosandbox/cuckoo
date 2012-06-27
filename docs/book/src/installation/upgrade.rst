===============================
Upgrade from a previous release
===============================

Cuckoo Sandbox grows really fast and in every release new features are added and
some others are fixed or removed.
If not otherwise specified in the release documentation, the suggested way to
upgrade your Cuckoo instance is to perform a fresh setup as described in
:doc:`index`.

The following steps are suggested:

1. Backup your installation.
2. Read the documentation shipped with the new release.
3. Make sure to have installed all required dependencies, otherwise install them.
4. Do a Cuckoo fresh installation of the Host components.
5. Reconfigure Cuckoo as explained in this book (copying old configuration files
   is not safe because options can change between releases).
6. Test it!

If something goes wrong you probably failed some steps during the fresh
installation or reconfiguration. Check again the procedure explained in this
book.

It's not recommended to rewrite an old Cuckoo installation with the latest
release files, as it might raise some problems because:

* You are overwriting Python source files (.py) but Pyhton bytecode files (.pyc)
  are still in place.
* There are configuration files changes acrosss the two versions.

