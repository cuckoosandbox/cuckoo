# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class PPT(Package):
    """PowerPoint analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office 15", "root", "office15", "POWERPNT.EXE"),
    ]

    def start(self, path):
        powerpoint = self.get_path("Microsoft Office PowerPoint")
        return self.execute(powerpoint, args=[path])
