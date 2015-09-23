# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER

from lib.common.abstracts import Package

class PDF(Package):
    """PDF analysis package."""
    PATHS = [
        ("ProgramFiles", "Adobe", "Reader 8.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 9.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 10.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 11.0", "Reader", "AcroRd32.exe"),
    ]

    REGKEYS = [
        [
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Adobe\\Acrobat Reader\\9.0\\AdobeViewer",
            {
                # Accept EULA for Adobe Reader 9.0.
                "EULA": 1,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "SOFTWARE\\Adobe\\Acrobat Reader\\9.0\\AdobeViewer",
            {
                # Accept EULA for Adobe Reader 9.0.
                "EULA": 1,
            },
        ],
    ]

    def start(self, path):
        reader = self.get_path("Adobe Reader")
        return self.execute(reader, args=[path], maximize=True)
