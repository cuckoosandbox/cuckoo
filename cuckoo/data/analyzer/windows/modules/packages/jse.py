# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class JScript(Package):
    """JScript analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .jse file extension as is required by wscript.
        if not path.endswith(".jse"):
            os.rename(path, path + ".jse")
            path += ".jse"
            log.info("Submitted file is missing extension, added .jse")

        return self.execute(wscript, args=[path], trigger="file:%s" % path)
