# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

class HTA(Package):
    """HTA analysis package."""
    PATHS = [
        ("System32", "mshta.exe"),
    ]

    def start(self, path):
        mshta = self.get_path("mshta")

        # Enforce .hta extension.
        if not path.endswith(".hta"):
            os.rename(path, path + ".hta")
            path += ".hta"

        return self.execute(mshta, args=[path])
