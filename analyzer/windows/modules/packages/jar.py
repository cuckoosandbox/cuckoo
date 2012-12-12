# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Jar(Package):
    """Java analysis package."""

    def get_path(self):
        paths = [
            os.path.join(os.getenv("ProgramFiles"), "Java", "jre6", "bin", "java.exe"),
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        return None

    def start(self, path):
        java = self.get_path()
        if not java:
            raise CuckooPackageError("Unable to find any Java executable available")

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
            raise CuckooPackageError("Unable to execute initial Java process, analysis aborted")

        if not free and suspended:
            p.inject()
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        return True
