# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Genric(Package):
    """Generic analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        dll = self.options.get("dll", None)
        suspended = True
        if free:
            suspended = False

        cmd_path = os.path.join(os.getenv("SystemRoot"), "system32", "cmd.exe")
        cmd_args = "/c start \"{0}\"".format(path)

        p = Process()
        if not p.execute(path=cmd_path, args=cmd_args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, "
                                     "analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            p.close()
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
