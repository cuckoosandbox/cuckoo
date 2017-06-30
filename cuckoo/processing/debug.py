# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import codecs
import json
import logging
import os

from cuckoo.common.abstracts import Processing
from cuckoo.common.constants import faq
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.core.database import Database

log = logging.getLogger(__name__)

class Logfile(list):
    def __init__(self, filepath, is_json=False):
        list.__init__(self)
        self.filepath = filepath
        self.is_json = is_json

    def __iter__(self):
        try:
            for line in codecs.open(self.filepath, "rb", "utf-8"):
                yield json.loads(line) if self.is_json else line
        except Exception as e:
            log.info("Error decoding %s: %s", self.filepath, e)

    def __nonzero__(self):
        return bool(os.path.getsize(self.filepath))

class Debug(Processing):
    """Analysis debug information."""
    order = 999

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        self.key = "debug"
        debug = {
            "log": [],
            "cuckoo": [],
            "action": [],
            "dbgview": [],
            "errors": [],
        }

        if os.path.exists(self.log_path):
            try:
                f = codecs.open(self.log_path, "rb", "utf-8")
                debug["log"] = f.readlines()
            except ValueError as e:
                raise CuckooProcessingError(
                    "Error decoding %s: %s" % (self.log_path, e)
                )
            except (IOError, OSError) as e:
                raise CuckooProcessingError(
                    "Error opening %s: %s" % (self.log_path, e)
                )
        else:
            log.error(
                "Error processing task #%d: it appears that the Virtual "
                "Machine hasn't been able to contact back to "
                "the Cuckoo Host. There could be a few reasons for this, "
                "please refer to our documentation on the matter: %s",
                self.task.id,
                faq("troubleshooting-vm-network-configuration"),
                extra={
                    "error_action": "vmrouting",
                    "action": "guest.communication",
                    "status": "error",
                    "task_id": self.task.id,
                }
            )

        if os.path.exists(self.cuckoolog_path):
            debug["cuckoo"] = Logfile(self.cuckoolog_path)

        dbgview_log = os.path.join(self.analysis_path, "logs", "dbgview.log")
        if os.path.exists(dbgview_log):
            f = open(dbgview_log, "rb")
            # Ignore the first line which identifies the machine.
            f.readline()
            for line in f:
                idx, time, message = line.split(None, 2)
                debug["dbgview"].append(message)

        debug["errors"] = []
        for error in Database().view_errors(self.task["id"]):
            if error.message and error.message not in debug["errors"]:
                debug["errors"].append(error.message)

            if error.action and error.action not in debug["action"]:
                debug["action"].append(error.action)

        if os.path.exists(self.mitmerr_path):
            mitmerr = open(self.mitmerr_path, "rb").read()
            if mitmerr and mitmerr not in debug["errors"]:
                debug["errors"].append(mitmerr)

        return debug
