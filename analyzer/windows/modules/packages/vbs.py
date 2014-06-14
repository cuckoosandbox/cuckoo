# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

# Originally proposed by kidrek:
# https://github.com/cuckoobox/cuckoo/pull/136

class VBS(Package):
    """VBS analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        dll = self.options.get("dll")
        free = self.options.get("free")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=wscript, args="\"{0}\"".format(path), suspended=suspended):
            raise CuckooPackageError("Unable to execute initial WScript "
                                     "process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
