# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class PDF(Package):
    """PDF analysis package."""
    PATHS = [
        ("ProgramFiles", "Adobe", "Reader 8.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 9.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 10.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 11.0", "Reader", "AcroRd32.exe"),
    ]

    def start(self, path):
        reader = self.get_path("Adobe Reader")
        dll = self.options.get("dll", None)
        free = self.options.get("free", False)
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=reader, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Adobe Reader "
                                     "process, analysis aborted.")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
