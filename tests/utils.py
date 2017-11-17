# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

class chdir(object):
    """Temporarily change the current directory."""

    def __init__(self, dirpath):
        self.dirpath = dirpath

    def __enter__(self):
        self.origpath = os.getcwd()
        os.chdir(self.dirpath)

    def __exit__(self, type_, value, traceback):
        os.chdir(self.origpath)
