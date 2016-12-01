# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import subprocess

from cuckoo.misc import cwd

def migrate_database(revision="head"):
    args = [
        "alembic", "-x", "cwd=%s" % cwd(), "upgrade", revision,
    ]
    try:
        subprocess.check_call(args, cwd=cwd("db_migration", private=True))
    except subprocess.CalledProcessError:
        return False
    return True
