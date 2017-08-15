# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os

from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.exceptions import CuckooDisableModule
from cuckoo.misc import cwd
from cuckoo.core.database import Database

log = logging.getLogger(__name__)


class Experiment(Auxiliary):

    def start(self):
        """"Creates a JSON file containing all files dropped and added
         as autorun on the VM in the previous analyses for an experiment"""

        if not self.task.experiment or not self.task.experiment.last_completed:
            log.debug("Not running for task %s. Not part of an experiment or"
                      " its first run.", self.task.id)
            raise CuckooDisableModule
        else:
            log.debug("Creating experiment.json using information from"
                      " previous tasks in this experiment")
            db = Database()
            tasks = db.list_tasks(experiment=self.task.experiment_id)
            possible_injectables = set()
            analysis_folder = cwd("storage", "analyses")

            for task in tasks:

                task_completed = os.path.join(analysis_folder, str(task.id))
                self._read_files(task_completed, possible_injectables)
                self._read_reboot(task_completed, possible_injectables)

            if len(possible_injectables) < 1:
                return

            exp_json = {
                "injectables": list(possible_injectables)
            }

            expfile_path = os.path.join(analysis_folder, str(self.task.id),
                                            "experiment.json")

            with open(expfile_path, "wb") as fw:
                json.dump(exp_json, fw, indent=2)

    def _read_reboot(self, folder, injectables_set):
        """Reads all file paths used to create a process on reboot
        from reboot.json"""
        reboot_path = os.path.join(folder, "reboot.json")
        if not os.path.exists(reboot_path):
            return

        with open(reboot_path, "rb") as fp:
            for line in fp:
                event = json.loads(line)
                if event["category"] != "create_process":
                    continue

                if "args" not in event or len(event["args"]) < 1:
                    continue

                injectables_set.add(event["args"][0])

    def _read_files(self, folder, injectables_set):
        """Reads the paths of all files dropped"""
        files_path = os.path.join(folder, "files.json")
        if not os.path.exists(files_path):
            return

        with open(files_path, "rb") as fp:
            for line in fp:
                file = json.loads(line)
                if not file["filepath"]:
                    continue

                injectables_set.add(file["filepath"])

    def cb_prepare_guest(self):
        """"Pushes the created injectables file to the guest to be used
        during the analysis"""
        injectables_path = cwd("storage", "analyses", str(self.task.id),
                               "experiment.json")

        if not os.path.exists(injectables_path):
            return

        log.debug("Preparing guest for task %s of experiment %s for next"
                  " analysis", self.task.id, self.task.experiment_id)

        files = {"file": open(injectables_path, "rb")}
        data = {"filepath": os.path.join(self.guest_manager.analyzer_path,
                                         "experiment.json")}
        self.guest_manager.post("/store", files=files, data=data)
