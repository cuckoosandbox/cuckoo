# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process

class Shellcode(Package):
    """Shellcode (any x86 executable code) analysis package."""

    def start(self, path):
        p = Process()
        p.execute(path="bin/execsc.exe", args=path, suspended=True)
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
