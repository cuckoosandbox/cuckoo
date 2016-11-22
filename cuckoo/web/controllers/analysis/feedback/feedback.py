# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import base64
import json
import requests
from datetime import datetime

from django.conf import settings

from cuckoo.common.constants import CUCKOO_VERSION
from controllers.analysis.analysis import AnalysisController
from controllers.analysis.export.export import ExportController

results_db = settings.MONGO

class AnalysisFeedBackController(object):
    """Contacts Cuckoo HQ with feedback + optional analysis dump"""

    def __init__(self, task_id):
        self._url_feedback = "https://cuckoo.sh/feedback/api/submit/"

        self.task_id = task_id
        self.email = None
        self.message = None
        self.company = None
        self.name = None
        self.include_analysis = False
        self.include_memdump = False
        self.feedback_automated = False

    def send(self):
        data = {
            "errors": [],
            "contact": {
                "email": self.email,
                "company": self.company,
                "name": self.name
            },
            "analysis_info": {},
            "automated": self.feedback_automated,
            "message": self.message
        }

        report = AnalysisController.get_report(self.task_id)
        if "feedback" in report["analysis"] and isinstance(report["analysis"]["feedback"], dict):
            raise Exception("Feedback previously sent")

        if "debug" in report["analysis"] and "errors" in report["analysis"]["debug"]:
            data["errors"] = report["analysis"]["debug"]["errors"]

        if self.include_analysis:
            analysis_path = report["analysis"]["info"]["analysis_path"]
            taken_dirs, taken_files = ExportController.get_files(analysis_path)

            if not self.include_memdump:
                taken_dirs = [z for z in taken_dirs if z[0] != "memory"]

            export = ExportController.create(task_id=self.task_id,
                                             taken_dirs=taken_dirs,
                                             taken_files=taken_files)
            # attach the zip file
            export.seek(0)
            data["export"] = base64.b64encode(export.read())

        # attach additional analysis information
        if "file" in report["analysis"]["target"]:
            data["analysis_info"]["file"] = {
                k: v for k, v in report["analysis"]["target"]["file"].items()
                if isinstance(v, (str, unicode, int, float))}
            data["analysis_info"]["file"]["task_id"] = self.task_id
        else:
            data["analysis_info"]["url"] = {"url": report["analysis"]["target"]["url"]}
            data["analysis_info"]["url"]["task_id"] = self.task_id

        feedback_id = self._send(data)
        return feedback_id

    def _send(self, data):
        headers = {
            "Content-type": "application/json",
            "Accept": "text/plain",
            "User-Agent": "Cuckoo %s" % CUCKOO_VERSION
        }

        resp = requests.post(url=self._url_feedback, json=data, headers=headers)
        if not resp.status_code == 200:
            raise Exception("the remote server did not respond correctly")

        resp = json.loads(resp.content)
        if not resp["status"]:
            raise Exception(resp["message"])

        feedback_id = resp["feedback_id"]
        self._feedback_sent(feedback_id)

        return feedback_id

    def _feedback_sent(self, feedback_id):
        return results_db.analysis.update_one(
            {"info.id": int(self.task_id)},
            {"$set": {"feedback": self.to_dict(), "feedback_id": feedback_id}})

    def to_dict(self):
        return {
            "email": self.email,
            "message": self.message,
            "include_memdump": self.include_memdump,
            "include_analysis": self.include_analysis,
            "date": datetime.now()
        }
