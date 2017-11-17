# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

class Generic(Package):
    """Generic analysis package. Uses shell based execution."""

    def __init__(self, *args, **kwargs):
        Package.__init__(self, *args, **kwargs)
        self.seen_pids = set()

    def start(self, path):
        os.chmod(path, 0o755)
        return self.execute(["sh", "-c", path])
