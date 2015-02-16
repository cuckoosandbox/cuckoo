# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Msi(Package):
    """MSI analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "msiexec.exe"),
    ]

    def start(self, path):
        msi_path = self.get_path("msiexec.exe")
        msi_args = "/I \"{0}\"".format(path)
        return self.execute(msi_path, msi_args)
