# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
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
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\9.0\\FeatureLockDown\\cDefaultLaunchAttachmentPerms",
            {
                # The file X may contain programs, macros, or viruses that
                # could potentially harm your computer. Open the file only if
                # you are sure it is safe. Would you like to: open..?
                "tBuiltInPermList": (
                    "version:1|.doc:2|.docm:2|.docx:2|.exe:2|.xls:2|.xlsx:2|"
                    ".bat:2|.ddl:2|.msi:2|.vb:2|.vbs:2|.wsf:2|.wsc:2|.js:2|"
                    ".wsh:2|.jar:2|.rar:2|.zip:2|.bat:2"
                ),
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
