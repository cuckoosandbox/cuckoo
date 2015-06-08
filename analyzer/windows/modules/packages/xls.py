# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class XLS(Package):
    """Excel analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "EXCEL.EXE"),
    ]

    def start(self, path):
        excel = self.get_path("Microsoft Office Excel")
        return self.execute(excel, args=[path])
