# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import logging
from datetime import datetime

from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)


class AnalysisInfo(Processing):
    """General information about analysis session."""

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        try:
            started = datetime.fromtimestamp(time.mktime(time.strptime(self.task["started_on"], "%Y-%m-%d %H:%M:%S")))
            ended = datetime.fromtimestamp(time.mktime(time.strptime(self.task["completed_on"], "%Y-%m-%d %H:%M:%S")))
        except:
            log.critical("Failed to get start/end time from Task.")
            # just set it to default timeout
            duration = -1
        else:
            duration = (ended - started).seconds

        info = {
            "version" : CUCKOO_VERSION,
            "started" : self.task["started_on"],
            "ended" : self.task.get("completed_on", "none"),
            "duration" : duration,
            "id" : int(self.task["id"]),
            "category" : self.task["category"]
        }

        return info
