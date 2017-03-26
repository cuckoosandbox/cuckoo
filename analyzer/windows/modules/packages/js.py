# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from _winreg import HKEY_CURRENT_USER
from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Javascript(Package):
    """Javascript analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    REGKEYS = [
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0",
            {
                "1201": 0,
            },
        ],
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .js file extension as is required by wscript.
        if not path.endswith(".js"):
            os.rename(path, path + ".js")
            path += ".js"
            log.info("Submitted file is missing extension, added .js")

        return self.execute(wscript, args=[path], trigger="file:%s" % path)
