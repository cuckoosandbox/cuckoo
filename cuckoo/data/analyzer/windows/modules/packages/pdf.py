# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from _winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class PDF(Package):
    """PDF analysis package."""
    PATHS = [
        ("ProgramFiles", "Adobe", "Reader 8.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 9.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 10.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Reader 11.0", "Reader", "AcroRd32.exe"),
        ("ProgramFiles", "Adobe", "Acrobat Reader DC", "Reader", "AcroRd32.exe"),
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

        # Enforce the .pdf file extension.
        if not path.endswith(".pdf"):
            os.rename(path, path + ".pdf")
            path += ".pdf"
            log.info("Submitted file is missing extension, added .pdf")

        return self.execute(
            reader, args=[path], maximize=True, mode="pdf",
            trigger="file:%s" % path
        )
