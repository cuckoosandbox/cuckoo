# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import logging
import json
from datetime import datetime

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_VERSION

log = logging.getLogger(__name__)

class AnalysisInfo(Processing):
    """General information about analysis session."""

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        if os.path.isfile(self.taskinfo_path):
            return json.load(open(self.taskinfo_path))

        if "started_on" not in self.task:
            return dict(
                version=CUCKOO_VERSION,
                started="none",
                ended="none",
                duration=-1,
                id=int(self.task["id"]),
                category="unknown",
                custom="unknown",
                machine=None,
                package="unknown"
            )

        if self.task.get("started_on") and self.task.get("completed_on"):
            started = self.task["started_on"]
            ended = self.task["completed_on"]
            duration = (ended - started).seconds
        else:
            log.critical("Failed to get start/end time from Task.")
            started, ended, duration = None, None, -1

        db = Database()

        # Fetch sqlalchemy object.
        task = db.view_task(self.task["id"], details=True)

        if task and task.guest:
            # Get machine description.
            machine = task.guest.to_dict()
            # Remove superfluous fields.
            del machine["task_id"]
            del machine["id"]
        else:
            machine = None

        return dict(
            version=CUCKOO_VERSION,
            started=self.task["started_on"],
            ended=self.task.get("completed_on", "none"),
            duration=duration,
            id=int(self.task["id"]),
            category=self.task["category"],
            custom=self.task["custom"],
            owner=self.task["owner"],
            machine=machine,
            package=self.task["package"],
            platform=self.task["platform"],
            options=self.task["options"],
            route=self.task["route"],
        )

class MetaInfo(Processing):
    """General information about the task and output files (memory dumps, etc)."""

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "metadata"

        def reformat(x):
            # kinda ugly absolute -> relative
            relpath = x[len(self.analysis_path):].lstrip("/")

            dirname = os.path.dirname(relpath)
            basename = os.path.basename(relpath)
            if not dirname: dirname = ""
            return dict(dirname=dirname, basename=basename, sha256=File(x).get_sha256())

        meta = {
            "output": {},
        }

        if os.path.exists(self.pcap_path):
            meta["output"]["pcap"] = reformat(self.pcap_path)

        for path, key in [
                (self.pmemory_path, "memdumps"),
                (self.buffer_path, "buffers"),
                (self.dropped_path, "dropped"),
            ]:
            if os.path.exists(path):
                contents = os.listdir(path)
                if contents:
                    results["output"][key] = [reformat(os.path.join(path, i)) for i in contents]

        return results
