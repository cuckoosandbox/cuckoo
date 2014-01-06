# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class CPL(Package):
    """Control Panel Applet analysis package."""

    def get_path(self):
        path = os.path.join(os.getenv("SystemRoot"), "system32", "control.exe")
        if os.path.exists(path):
            return path

        return

    def start(self, path):
        control = self.get_path()
        if not control:
            raise CuckooPackageError("Unable to find any control.exe "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=control, args="\"%s\"" % path,
                         suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Control "
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
