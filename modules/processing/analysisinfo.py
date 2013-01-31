# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
from datetime import datetime

from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.core.database import Database

class AnalysisInfo(Processing):
    """General information about analysis session."""

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        started = datetime.fromtimestamp(time.mktime(time.strptime(self.task["started_on"], "%Y-%m-%d %H:%M:%S")))
        ended = datetime.fromtimestamp(time.mktime(time.strptime(self.task["completed_on"], "%Y-%m-%d %H:%M:%S")))
        duration =  ended - started

        info = {
            "version" : CUCKOO_VERSION,
            "started" : self.task["started_on"],
            "ended" : self.task["completed_on"],
            "duration" : duration.seconds,
            "id" : int(self.task["id"]),
            "category" : self.task["category"]
        }

        return info
