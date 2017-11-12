# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import HKEY_CURRENT_USER

from lib.common.abstracts import Package

class HWP(Package):
    """Hangul (Korean) Word Processor File 5.x analysis package."""
    PATHS = [
        ("ProgramFiles", "Hnc", "Hwp80", "Hwp.exe"),
    ]

    def start(self, path):
        word = self.get_path("Hangul (Korean) Word Processor File 5.x")
        return self.execute(
            word, args=[path], mode="office", trigger="file:%s" % path
        )
