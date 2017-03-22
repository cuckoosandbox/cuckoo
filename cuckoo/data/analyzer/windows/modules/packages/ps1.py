# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

# Originally proposed by David Maciejak.

class PS1(Package):
    """PowerShell analysis package."""
    PATHS = [
        ("System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ("System32", "WindowsPowerShell", "v2.0", "powershell.exe"),
        ("System32", "WindowsPowerShell", "v3.0", "powershell.exe"),
    ]

    def start(self, path):
        powershell = self.get_path("PowerShell")
        args = [
            "-NoProfile", "-ExecutionPolicy", "unrestricted", "-File", path
        ]
        return self.execute(powershell, args=args, trigger="file:%s" % path)
