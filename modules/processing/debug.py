# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Processing

class Debug(Processing):
    """Analysis debug information."""

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        self.key = "debug"
        debug = {}

        if os.path.exists(self.log_path):
            with open(self.log_path, "rb") as log:
                debug["log"] = log.read()
        else:
            debug["log"] = ""

        return debug
