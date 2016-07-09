# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDisableModule

log = logging.getLogger(__name__)

class Reboot(Auxiliary):
    def start(self):
        if self.task.package != "reboot":
            raise CuckooDisableModule

    def cb_legacy_agent(self):
        log.error(
            "Reboot analysis is not backwards compatible with the Old Agent, "
            "please upgrade your target machine (%s) to the New Agent to use "
            "the reboot analysis capabilities.", self.machine
        )
        raise CuckooDisableModule

    def _push_dropped_files(self, analysis_path):
        files_json = os.path.join(analysis_path, "files.json")
        if not os.path.exists(files_json):
            return

        # Push dropped files through.
        for line in open(files_json, "rb"):
            entry = json.loads(line)

            # Screenshots etc.
            if not entry["filepath"]:
                continue

            filepath = os.path.join(analysis_path, entry["path"])

            data = {
                "filepath": entry["filepath"],
            }
            files = {
                "file": open(filepath, "rb"),
            }
            self.guest_manager.post("/store", files=files, data=data)

    def cb_prepare_guest(self):
        log.info("Preparing task #%d for a reboot analysis..", self.task.id)

        analysis_path = os.path.join(
            CUCKOO_ROOT, "storage", "analyses", self.task.custom
        )

        self._push_dropped_files(analysis_path)

        # Push the reboot.json file to the Analyzer.
        files = {
            "file": open(os.path.join(analysis_path, "reboot.json"), "rb"),
        }
        reboot_path = os.path.join(
            self.guest_manager.analyzer_path, "reboot.json"
        )
        data = {
            "filepath": reboot_path,
        }
        self.guest_manager.post("/store", files=files, data=data)
