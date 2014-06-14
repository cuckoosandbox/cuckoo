# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class DOC(Package):
    """Word analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def start(self, path):
        word = self.get_path("Microsoft Office Word")
        dll = self.options.get("dll")
        free = self.options.get("free")
        suspended = True
        if free:
            suspended = False

        p = Process()
        if not p.execute(path=word, args="\"%s\"" % path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Microsoft "
                                     "Office Word process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
