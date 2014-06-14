# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Jar(Package):
    """Java analysis package."""
    PATHS = [
        ("ProgramFiles", "Java", "jre7", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre6", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path("Java")
        dll = self.options.get("dll")
        free = self.options.get("free")
        class_path = self.options.get("class")
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
                                     "process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
