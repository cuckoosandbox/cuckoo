# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import HKEY_CURRENT_USER

from lib.common.abstracts import Package

class PPT(Package):
    """PowerPoint analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office10", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office16", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office 15", "root", "office15", "POWERPNT.EXE"),
    ]

    REGKEYS = [
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\12.0\\Common\\General",
            {
                # "Welcome to the 2007 Microsoft Office system"
                "ShownOptIn": 1,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\12.0\\Powerpoint\\Security",
            {
                # Enable VBA macros in Office 2007.
                "VBAWarnings": 1,
                "AccessVBOM": 1,

                # "The file you are trying to open .xyz is in a different
                # format than specified by the file extension. Verify the file
                # is not corrupted and is from trusted source before opening
                # the file. Do you want to open the file now?"
                "ExtensionHardening": 0,
            },
        ],
    ]

    def start(self, path):
        powerpoint = self.get_path("Microsoft Office PowerPoint")
        return self.execute(
            powerpoint, args=["/S", path], mode="office",
            trigger="file:%s" % path
        )
