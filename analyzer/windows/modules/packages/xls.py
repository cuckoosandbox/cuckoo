# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process

class XLS(Package):
    """Excel analysis package."""

    def get_path(self):
        paths = [
            os.path.join(os.getenv("ProgramFiles"), "Microsoft Office", "EXCEL.EXE"),
            os.path.join(os.getenv("ProgramFiles"), "Microsoft Office", "Office11", "EXCEL.EXE"),
            os.path.join(os.getenv("ProgramFiles"), "Microsoft Office", "Office12", "EXCEL.EXE"),
            os.path.join(os.getenv("ProgramFiles"), "Microsoft Office", "Office14", "EXCEL.EXE"),
            os.path.join(os.getenv("ProgramFiles"), "Microsoft Office", "Office15", "EXCEL.EXE")
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        excel = self.get_path()
        if not excel:
            raise CuckooPackageError("Unable to find any Microsoft Office Excel executable available")

        free = self.options.get("free", False)
        dll = self.options.get("dll")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=excel, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Microsoft Office Excel process, analysis aborted")

        if not free and suspended:
            if dll:
                p.inject(os.path.join("dll", dll))
            else:
                p.inject()
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
