# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Python(Package):
    """Python analysis package."""
    PATHS = [
        ("C:", "Python27", "python.exe"),
    ]

    def start(self, path):
        python = self.get_path("Python")
        free = self.options.get("free")
        arguments = self.options.get("arguments", "")
        dll = self.options.get("dll")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=python,
                         args="%s %s" % (path, arguments),
                         suspended=suspended):
            raise CuckooPackageError("Unable to execute python, "
                                     "analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
