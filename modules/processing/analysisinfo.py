# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import codecs
import time
import json
import logging
import os
from datetime import datetime

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_VERSION

log = logging.getLogger(__name__)

class AnalysisInfo(Processing):
    """General information about analysis session."""

    def had_timeout(self):
        """ Test if the analysis had a timeout
        """
        if os.path.exists(self.log_path):
            try:
                log = codecs.open(self.log_path, "rb", "utf-8").read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" %
                                            (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" %
                                            (self.log_path, e))
        if "INFO: Analysis timeout hit, terminating analysis" in log:
            return True
        return False

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        try:
            started = time.strptime(self.task["started_on"], "%Y-%m-%d %H:%M:%S")
            started = datetime.fromtimestamp(time.mktime(started))
            ended = time.strptime(self.task["completed_on"], "%Y-%m-%d %H:%M:%S")
            ended = datetime.fromtimestamp(time.mktime(ended))
        except:
            log.critical("Failed to get start/end time from Task.")
            duration = -1
        else:
            duration = (ended - started).seconds

        db = Database()

        task = db.view_task(self.task["id"], details=True)
        if task:
            entry = task.to_dict()

            machine = db.view_machine(name=entry["machine"])
            if machine:
                self.task["machine"] = machine.to_dict()
                self.task["machine"]["id"] = int(self.task["machine"]["id"])
            else: 
                self.task["machine"] = {}
        else:
            self.task["machine"] = {}

        return dict(
            version=CUCKOO_VERSION,
            started=self.task["started_on"],
            ended=self.task.get("completed_on", "none"),
            duration=duration,
            id=int(self.task["id"]),
            category=self.task["category"],
            custom=self.task["custom"],
            machine=self.task["machine"],
            package=self.task["package"],
            timeout=self.had_timeout()
        )
