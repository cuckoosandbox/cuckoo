# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import platform

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class HTML(Package):
    """HTML file analysis package."""

    def start(self, path):
        free = self.options.get("free", False)
        dll = self.options.get("dll", None)
        suspended = True
        if free:
            suspended = False

        iex86 = os.path.join(os.getenv("Program Files(x86)"), "Internet Explorer", "iexplore.exe")       
        ie32 = os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe")
        
        if os.path.exists(iex86):
            iexplore = iex86
        else:
            iexplore = ie32
        p = Process()
        if not p.execute(path=iexplore, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet "
                                     "Explorer process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None

    def check(self):
        return True

    def finish(self):
        if self.options.get("procmemdump", False):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        return True
