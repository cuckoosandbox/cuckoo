# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Genric(Package):
    """Generic analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        free = self.options.get("free", False)
        dll = self.options.get("dll", None)
        suspended = True
        if free:
            suspended = False

        cmd_path = self.get_path("cmd.exe")
        cmd_args = "/c start \"{0}\"".format(path)

        p = Process()
        if not p.execute(path=cmd_path, args=cmd_args, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial process, "
                                     "analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            p.close()
            return p.pid
        else:
            return None
