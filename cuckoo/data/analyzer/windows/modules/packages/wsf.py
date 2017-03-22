# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class WSF(Package):
    """Windows Scripting File analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .wsf file extension as is required by wscript.
        if not path.endswith(".wsf"):
            os.rename(path, path + ".wsf")
            path += ".wsf"
            log.info("Submitted file is missing extension, added .wsf")

        return self.execute(wscript, args=[path], trigger="file:%s" % path)
