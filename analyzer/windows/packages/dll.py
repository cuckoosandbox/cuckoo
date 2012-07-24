# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process

class Dll(Package):
    """DLL analysis package."""

    def start(self, path):
        p = Process()

        rundll32 = "C:\\WINDOWS\\system32\\rundll32.exe"

        if "function" in self.options:
            p.execute(path=rundll32, args="%s,%s" % (path, self.options["function"]), suspended=True)
        else:
            p.execute(path=rundll32, args="%s,DllMain" % path, suspended=True)

        inject = True
        if "free" in self.options:
            if self.options["free"] == "yes":
                inject = False

        if inject:
            p.inject()

        p.resume()

        return p.pid

    def check(self):
        return True

    def finish(self):
        return True
