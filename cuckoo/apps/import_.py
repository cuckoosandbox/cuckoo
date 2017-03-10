# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from cuckoo.common.config import Config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.compat.config import migrate as migrate_conf
from cuckoo.misc import cwd

def identify(dirpath):
    filepath = os.path.join(dirpath, "lib", "cuckoo", "common", "constants.py")
    if os.path.exists(filepath):
        for line in open(filepath, "rb"):
            if line.startswith("CUCKOO_VERSION"):
                return line.split('"')[1]

def import_cuckoo(username, dirpath, force, database):
    version = identify(dirpath)
    if not version:
        raise CuckooOperationalError(
            "The path that you specified is not a proper Cuckoo setup. Please "
            "point the path to the root of your older Cuckoo setup, i.e., to "
            "the directory containing the cuckoo.py script!"
        )

    # TODO Copy over the configuration and ignore the database.
    if version in ("0.4", "0.4.1", "0.4.2"):
        raise CuckooOperationalError(
            "Importing from version 0.4, 0.4.1, or 0.4.2 is not supported as "
            "there are no database migrations for that version. Please start "
            "from scratch, your configuration would have been obsolete anyway!"
        )

    if os.path.isdir(cwd()) and os.listdir(cwd()):
        raise CuckooOperationalError(
            "This Cuckoo Working Directory already exists. Please import to "
            "a new/clean Cuckoo Working Directory."
        )

    # Following are various recursive imports.
    from cuckoo.apps import migrate_database
    from cuckoo.main import cuckoo_create

    # Port the older configuration.
    cfg = Config.from_confdir(os.path.join(dirpath, "conf"), loose=True)
    cfg = migrate_conf(cfg, version)

    # Create a fresh Cuckoo Working Directory.
    cuckoo_create(username, cfg)

    # Link or copy all of the older results to the new CWD.

    # Run database migrations. TODO Actually make it work.
    if not migrate_database():
        raise CuckooOperationalError(
            "Error migrating your old Cuckoo database!"
        )

    # Urge the user to run the community command. TODO Prettify output.
    print "You have successfully imported your old version of Cuckoo!"
    print "However, in order to get up-to-date, you'll probably want to"
    print "run the community command by running 'cuckoo community' manually."
    print "The community command will fetch the latest monitoring updates"
    print "as well as the latest Cuckoo Signatures."
