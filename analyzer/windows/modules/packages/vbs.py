# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

# Originally proposed by kidrek:
# https://github.com/cuckoobox/cuckoo/pull/136

class VBS(Package):
    """VBS analysis package."""

    def get_path(self):
        paths = [
            os.path.join(os.getenv("SystemRoot"), "system32", "wscript.exe")
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        wscript = self.get_path()
        if not wscript:
            raise CuckooPackageError("Unable to find any WScript "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=wscript, args="\"{0}\"".format(path), suspended=suspended):
            raise CuckooPackageError("Unable to execute initial WScript "
                                     "process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
