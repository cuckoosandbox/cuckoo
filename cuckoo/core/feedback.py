# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import base64
import json
import requests

from django.conf import settings

from cuckoo.common.config import Config
from cuckoo.common.constants import CUCKOO_VERSION
from cuckoo.common.exceptions import CuckooFeedbackError
from controllers.analysis.analysis import AnalysisController
from controllers.analysis.export.export import ExportController

log = logging.getLogger(__name__)
results_db = settings.MONGO

class CuckooFeedback(object):
    """Contacts Cuckoo HQ with feedback + optional analysis dump"""

    def __init__(self):
        self.cfg = Config("cuckoo")

    def send(self, analysis_id=None, name="", email="", message="", company="",
             include_json_report=False, include_analysis=False,
             include_memdump=False, was_automated=False):
        if not self.cfg.feedback.enabled:
            return
        if not name:
            name = self.cfg.feedback.name
        if not email:
            email = self.cfg.feedback.email
        if not company:
            company = self.cfg.feedback.company

        feedback = CuckooFeedbackObject(
            name=name,
            company=company,
            email=email,
            message=message,
            was_automated=was_automated
        )

        if include_json_report:
            if not analysis_id or not isinstance(analysis_id, int):
                raise CuckooFeedbackError("analysis_id cannot be empty while including the json_report")

            if feedback.already_submitted(analysis_id):
                raise CuckooFeedbackError("Feedback has already been submitted for this analysis")

            feedback.include_report(analysis_id=analysis_id)

        if include_analysis:
            feedback.include_analysis(include_memdump=include_memdump)

        feedback_id = self._send(feedback)
        return feedback_id

    def _send(self, feedback):
        feedback = feedback.to_dict()
        headers = {
            "Content-type": "application/json",
            "Accept": "text/plain",
            "User-Agent": "Cuckoo %s" % CUCKOO_VERSION
        }

        try:
            resp = requests.post(
                url=self.cfg.feedback.endpoint,
                json=feedback,
                headers=headers)
            if not resp.status_code == 200:
                raise Exception("the remote server did not respond correctly")

            resp = json.loads(resp.content)
            if not resp["status"]:
                raise Exception(resp["message"])

            feedback_id = resp["feedback_id"]
            if feedback.report_info.haskey("analysis_id"):
                self._register_sent(feedback=feedback,
                                    feedback_id=feedback_id,
                                    analysis_id=feedback.report_info["analysis_id"])
            return feedback_id
        except requests.exceptions.RequestException as e:
            log.error("Invalid response from Cuckoo feedback server: %s", e)

    def _register_sent(self, feedback, feedback_id, analysis_id):
        data = feedback.to_dict()
        if "export" in data:
            data.pop("export", None)

        return results_db.analysis.update_one(
            {"info.id": int(analysis_id)},
            {"$set": {"feedback": data, "feedback_id": feedback_id}})

class CuckooFeedbackObject:
    def __init__(self, name=None, company=None, email=None, message=None, was_automated=False):
        self.message = message
        self.memdump = None
        self.was_automated = was_automated
        self.errors = []
        self.contact = {
            "name": name,
            "company": company,
            "email": email,
        }

        self.report_info = {}
        self.report = None

    def include_report(self, analysis_id):
        report = AnalysisController.get_report(analysis_id)
        self.report = report

        if "debug" in report["analysis"] and "errors" in report["analysis"]["debug"]:
            for error in report["analysis"]["debug"]["errors"]:
                self.add_error(error)

        # attach additional analysis information
        if "file" in report["analysis"]["target"]:
            self.report_info["file"] = {
                k: v for k, v in report["analysis"]["target"]["file"].items()
                if isinstance(v, (str, unicode, int, float))}
            self.report_info["file"]["task_id"] = analysis_id
        else:
            self.report_info["url"] = {"url": report["analysis"]["target"]["url"]}
            self.report_info["url"]["task_id"] = analysis_id

        self.report_info["analysis_id"] = report["analysis"]["info"]["id"]
        self.report_info["analysis_path"] = report["analysis"]["info"]["analysis_path"]

    def add_error(self, error):
        self.errors.append(error)

    def include_analysis(self, include_memdump=False):
        if not self.report:
            raise CuckooFeedbackError(
                "Report must first be included in order to include the analysis")
        analysis_path = self.report_info["analysis_path"]
        taken_dirs, taken_files = ExportController.get_files(analysis_path)

        if not include_memdump:
            taken_dirs = [z for z in taken_dirs if z[0] != "memory"]

        export = ExportController.create(task_id=self.report["analysis"]["info"]["id"],
                                         taken_dirs=taken_dirs,
                                         taken_files=taken_files)
        export.seek(0)
        self.memdump = base64.b64encode(export.read())

    @staticmethod
    def already_submitted(analysis_id):
        report = AnalysisController.get_report(analysis_id)
        if not "analysis" in report:
            return
        elif "feedback" in report["analysis"] and \
                isinstance(report["analysis"]["feedback"], dict):
            return True

    def to_dict(self):
        data = {
            "errors": self.errors,
            "contact": self.contact,
            "automated": self.was_automated,
            "message": self.message
        }

        if self.report:
            data["analysis_info"] = self.report_info

        if self.memdump:
            data["export"] = self.memdump
