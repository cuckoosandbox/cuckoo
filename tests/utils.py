# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.misc import mkdir, cwd

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
