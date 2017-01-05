# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil
import subprocess

from cuckoo.misc import cwd

log = logging.getLogger(__name__)

def migrate_database(revision="head"):
    args = [
        "alembic", "-x", "cwd=%s" % cwd(), "upgrade", revision,
    ]
    try:
        subprocess.check_call(args, cwd=cwd("db_migration", private=True))
    except subprocess.CalledProcessError:
        return False
    return True

def import_legacy_analyses(dirpath, mode="copy"):
    """Imports the raw results of a legacy analysis. Either a symlink (on
    systems that support those) or a real copy may be used for the import."""
    if mode not in ("copy", "symlink"):
        raise RuntimeError(
            "Import mode should be either 'copy' or 'symlink'."
        )

    if mode == "symlink" and hasattr(os, "symlink"):
        copy = os.symlink
    else:
        copy = shutil.copytree

    analyses = os.path.join(dirpath, "storage", "analyses")
    if not os.path.isdir(analyses):
        log.warning("Didn't find any analyses, so not much to import!")
        return

    tasks = []
    for task_id in os.listdir(analyses):
        if task_id == "latest":
            continue

        copy(os.path.join(analyses, task_id), cwd(analysis=task_id))
        tasks.append(int(task_id))
    return tasks
