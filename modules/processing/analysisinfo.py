# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
from datetime import datetime

from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.abstracts import Processing

class AnalysisInfo(Processing):
    """General information about analysis session."""

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        started = float(self.cfg.analysis.started)
        ended = time.time()

        info = {
            "version" : CUCKOO_VERSION,
            "started" : datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S"),
            "ended" : datetime.fromtimestamp(ended).strftime("%Y-%m-%d %H:%M:%S"),
            "duration" : "%d seconds" % (ended - started),
            "id" : int(self.cfg.analysis.id),
            "category" : self.cfg.analysis.category
        }

        return info
