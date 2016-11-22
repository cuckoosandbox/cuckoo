# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Javascript(Package):
    """Javascript analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")

        # Enforce the .js file extension as is required by wscript.
        if not path.endswith(".js"):
            os.rename(path, path + ".js")
            path += ".js"
            log.info("Submitted file is missing extension, added .js")

        return self.execute(wscript, args=[path], trigger="file:%s" % path)
