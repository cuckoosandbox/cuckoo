# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class CPL(Package):
    """Control Panel Applet analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "control.exe"),
    ]

    def start(self, path):
        control = self.get_path("control.exe")
        dll = self.options.get("dll")
        free = self.options.get("free")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=control, args="\"%s\"" % path,
                         suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Control "
                                     "process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
