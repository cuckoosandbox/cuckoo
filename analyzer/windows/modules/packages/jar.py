# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Jar(Package):
    """Java analysis package."""

    def get_path(self):
        java = os.path.join(os.getenv("ProgramFiles"), "Java")
        paths = [
            os.path.join(java, "jre7", "bin", "java.exe"),
            os.path.join(java, "jre6", "bin", "java.exe"),
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        java = self.get_path()
        if not java:
            raise CuckooPackageError("Unable to find any Java "
                                     "executable available")

        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        class_path = self.options.get("class", None)
        suspended = True
        if free:
            suspended = False

        if class_path:
            args = "-cp \"%s\" %s" % (path, class_path)
        else:
            args = "-jar \"%s\"" % path

        p = Process()
        if not p.execute(path=java, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Java "
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
