# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

# Originally proposed by David Maciejak.

class PS1(Package):
    """PowerShell analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v2.0", "powershell.exe"),
        ("SystemRoot", "system32", "WindowsPowerShell", "v3.0", "powershell.exe"),
    ]

    def start(self, path):
        powershell = self.get_path("PowerShell")
        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        args = "-NoProfile -ExecutionPolicy unrestricted -File \"{0}\"".format(path)

        p = Process()
        if not p.execute(path=powershell, args=args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial PowerShell process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
