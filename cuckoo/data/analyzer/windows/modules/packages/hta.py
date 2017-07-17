# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class hta(Package):
    """HTA analysis package."""
    PATHS = [
        ("System32", "mshta.exe"),
    ]

    def start(self, path):
        mshta = self.get_path("mshta")
        return self.execute(mshta, args=[path])
