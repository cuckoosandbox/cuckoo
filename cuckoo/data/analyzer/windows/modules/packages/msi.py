# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Msi(Package):
    """MSI analysis package."""

    PATHS = [
        ("System32", "msiexec.exe"),
    ]

    def start(self, path):
        msi_path = self.get_path("msiexec.exe")
        return self.execute(msi_path, args=["/I", path])
