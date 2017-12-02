# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from cuckoo.misc import mkdir, cwd, load_signatures

class chdir(object):
    """Temporarily change the current directory."""

    def __init__(self, dirpath):
        self.dirpath = dirpath

    def __enter__(self):
        self.origpath = os.getcwd()
        os.chdir(self.dirpath)

    def __exit__(self, type_, value, traceback):
        os.chdir(self.origpath)

def init_analysis(task_id, package, *filename):
    """Initializes an analysis with an "encrypted" binary from tests/files/."""
    mkdir(cwd(analysis=task_id))
    content = open(os.path.join("tests", "files", *filename), "rb").read()
    open(cwd("binary", analysis=task_id), "wb").write(content[::-1])

def reload_signatures():
    sys.modules.pop("signatures", None)
    sys.modules.pop("signatures.android", None)
    sys.modules.pop("signatures.cross", None)
    sys.modules.pop("signatures.darwin", None)
    sys.modules.pop("signatures.extractor", None)
    sys.modules.pop("signatures.linux", None)
    sys.modules.pop("signatures.network", None)
    sys.modules.pop("signatures.windows", None)
    load_signatures()
