# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Shellcode(Package):
    """Shellcode (any x86 executable code) analysis package."""

    def start(self, path):
        return self.execute("bin/execsc.exe", args=[path])
