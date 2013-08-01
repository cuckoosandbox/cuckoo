# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.common.abstracts import Package
from lib.api.process import Process

class Shellcode(Package):
    """Shellcode (any x86 executable code) analysis package."""

    def start(self, path):
        p = Process()

        suspended = True
	free = self.options.get("free", False)

        if free:
            suspended = False

        p.execute(path=os.path.join("C:\WINDOWS\system32\WScript.exe"), args=" \"%s\"" % path, suspended=suspended)
        
        p.inject()
        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
