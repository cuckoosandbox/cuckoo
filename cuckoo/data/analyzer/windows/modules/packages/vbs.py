# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class VBS(Package):
    """VBS analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        if not path.endswith(".vbs"):
            os.rename(path, path + ".vbs")
            path += ".vbs"
            log.info("Submitted file is missing extension, added .vbs")

        return self.execute(wscript, args=[path], trigger="file:%s" % path)
