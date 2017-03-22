# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import HKEY_CURRENT_USER

from lib.common.abstracts import Package

class PUB(Package):
    """Word analysis package."""
    PATHS = [
        ("ProgramFiles", "Microsoft Office", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office10", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office11", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office12", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office14", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office15", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office16", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office 15", "root", "office15", "MSPUB.EXE"),
        ("ProgramFiles", "Microsoft Office", "root", "Office16", "MSPUB.EXE"),
    ]

    REGKEYS = [
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\12.0\\Publisher\\Security",
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
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\15.0\\Publisher\\Security",
            {
                # Enable VBA macros in Office 2013.
                "VBAWarnings": 1,
                "AccessVBOM": 1,

                # "The file you are trying to open .xyz is in a different
                # format than specified by the file extension. Verify the file
                # is not corrupted and is from trusted source before opening
                # the file. Do you want to open the file now?"
                "ExtensionHardening": 0,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Office\\16.0\\Publisher\\Security",
            {
                # Enable VBA macros in Office 2016.
                "VBAWarnings": 1,
                "AccessVBOM": 1,
            },
        ],
    ]

    def start(self, path):
        publisher = self.get_path("Microsoft Office Publisher")
        return self.execute(
            publisher, args=["/o", path], mode="office", trigger="file:%s" % path
        )
