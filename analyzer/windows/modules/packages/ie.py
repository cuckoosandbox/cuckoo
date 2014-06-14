# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class IE(Package):
    """Internet Explorer analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, url):
        iexplore = self.get_path("Internet Explorer")
        free = self.options.get("free")
        dll = self.options.get("dll")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=iexplore, args="\"%s\"" % url, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet "
                                     "Explorer process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
