# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class PDF(Package):
    """PDF analysis package."""

    def get_path(self):
        adobe = os.path.join(os.getenv("ProgramFiles"), "Adobe")
        paths = [
            os.path.join(adobe, "Reader 8.0", "Reader", "AcroRd32.exe"),
            os.path.join(adobe, "Reader 9.0", "Reader", "AcroRd32.exe"),
            os.path.join(adobe, "Reader 10.0", "Reader", "AcroRd32.exe"),
            os.path.join(adobe, "Reader 11.0", "Reader", "AcroRd32.exe"),
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        reader = self.get_path()
        if not reader:
            raise CuckooPackageError("Unable to find any Adobe Reader "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=reader, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Adobe Reader "
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
