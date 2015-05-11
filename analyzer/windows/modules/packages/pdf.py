# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

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
        return self.execute(reader, args=[path])
