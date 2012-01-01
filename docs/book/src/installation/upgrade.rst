=============================
Upgrade from previous release
=============================

Cuckoo Sandbox grows really fast in each release, new features are added and some other are fixed or changed.
If not indicated in release documentation, the suggested way to upgrade your Cuckoo installation is to run a fresh setup as described :doc:`index`.
The following steps are suggested:

1. Backup your installation.
2. Read the documentation shipped with the new Cuckoo release.
3. Ensure to have installed all required dependencies, otherwise install them.
4. Do a Cuckoo fresh installation in both host and guests.
5. Reconfigure Cuckoo as explained in this book (copying old configuration files is not safe because options can change between releases).
6. Test it!

If something goes wrong probably you fail a step during the fresh installation or reconfiguration. Check your steps
with this book.

Never try to rewrite an old Cuckoo installation with the latest release files, if you do that without the needed knowledge 
probably you can break your setup, for example because:

* You are overwriting Python (.py) files but Pyhton compiled (.pyc) files are still in place.
* There are configuration files changes between each release.

So remember to always run a fresh installation if the new Cuckoo release doesn't come with an ad-hoc upgrade procedure. 