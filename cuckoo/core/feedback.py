# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import base64
import json
import requests
import traceback
from glob import glob

from django.template import TemplateSyntaxError, TemplateDoesNotExist
from django.conf import settings
from django.http import Http404

from cuckoo.misc import cwd
from cuckoo.core.report import AbstractReport
from cuckoo.common.config import Config
from cuckoo.common.constants import CUCKOO_VERSION
from cuckoo.common.exceptions import CuckooFeedbackError
from controllers.analysis.analysis import AnalysisController
from controllers.analysis.export.export import ExportController

from cuckoo.common.exceptions import (
    CuckooCriticalError,
    CuckooStartupError,
    CuckooDatabaseError,
    CuckooDependencyError,
    CuckooOperationalError,
    CuckooMachineError,
    CuckooAnalysisError,
    CuckooProcessingError,
    CuckooReportError,
    CuckooGuestError,
    CuckooResultError,
    CuckooDisableModule,
    CuckooFeedbackError
)

log = logging.getLogger(__name__)
results_db = settings.MONGO

class CuckooFeedback(object):
    """Contacts Cuckoo HQ with feedback + optional analysis dump"""

    def __init__(self):
        self.cfg = Config("cuckoo")

    def send_exception(self, exception, request=None):
        """
        To be used during exception handling.
        @param exception: The exception class
        @param request: Django request object
        @return:
        """
        feedback = CuckooFeedbackObject(was_automated=True)
        feedback.message = "Exception `%s` encountered" % str(type(exception))

        if isinstance(exception, (CuckooFeedbackError, Http404)):
            return
        elif isinstance(exception, (TemplateDoesNotExist,
                                    TemplateSyntaxError)):
            feedback.add_error("Django templating error")

        feedback.add_error(traceback.format_exc())
        feedback_options = {
            "include_analysis": False,
            "include_json_report": False,
            "include_memdump": False,
            "include_config": True
        }

        if request and hasattr(request, "resolver_match"):
            if request.method == "POST" and request.is_ajax():
                request_kwargs = json.loads(request.body)
            else:
                request_kwargs = request.resolver_match.kwargs

            if "task_id" in request_kwargs:
                task_id = int(request_kwargs["task_id"])
            elif "analysis_id" in request_kwargs:
                task_id = int(request_kwargs["analysis_id"])
            else:
                task_id = None

            if task_id:
                feedback_options["analysis_id"] = task_id
                feedback_options["include_analysis"] = True
                feedback_options["include_json_report"] = True
                feedback_options["include_memdump"] = False

        if feedback_options["include_json_report"]:
            feedback.include_report(analysis_id=feedback_options["analysis_id"])

        if feedback_options["include_analysis"]:
            feedback.include_analysis(include_memdump=feedback_options["include_memdump"])

        self._send(feedback)

    def send(self, analysis_id=None, name="", email="", message="", company="",
             include_json_report=False, include_analysis=False,
             include_memdump=False, was_automated=False):
        if not self.cfg.feedback.enabled:
            return

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
        if not feedback.validate():
            raise CuckooFeedbackError("Feedback object could not be validated")

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
                raise CuckooFeedbackError("the remote server did not respond correctly")

            resp = json.loads(resp.content)
            if not resp["status"]:
                raise CuckooFeedbackError(resp["message"])

            feedback_id = resp["feedback_id"]
            if feedback.report_info.haskey("analysis_id"):
                self._register_sent(feedback=feedback,
                                    feedback_id=feedback_id,
                                    analysis_id=feedback.report_info["analysis_id"])
            return feedback_id
        except requests.exceptions.RequestException as e:
            log.error("Invalid response from Cuckoo feedback server: %s", str(e))
        except CuckooFeedbackError as e:
            log.error("Cuckoo feedback error while sending: %s", str(e))
        except Exception as e:
            log.error("Unknown feedback error while sending: %s" % str(e))

    def _register_sent(self, feedback, feedback_id, analysis_id):
        data = feedback.to_dict()
        if "export" in data:
            data.pop("export", None)

        return results_db.analysis.update_one(
            {"info.id": int(analysis_id)},
            {"$set": {"feedback": data, "feedback_id": feedback_id}})

class CuckooFeedbackObject:
    def __init__(self, message=None, email=None, name=None, company=None, was_automated=False):
        self.was_automated = was_automated
        self.message = message
        self.errors = []
        self.cfg = None
        self.include_config()
        self.contact = {
            "name": self.cfg["cuckoo"]["feedback"]["name"] if not name else name,
            "company": self.cfg["cuckoo"]["feedback"]["company"] if not company else company,
            "email": self.cfg["cuckoo"]["feedback"]["email"] if not email else email
        }
        self.export = None
        self.report_info = {}
        self.report = None

    def include_report(self, analysis_id):
        report = AbstractReport(analysis_id=analysis_id)
        if report.analysis_errors:
            for error in report.analysis_errors:
                self.add_error(error)

        # attach additional analysis information
        if "file" in report.analysis_target:
            self.report_info["file"] = {
                k: v for k, v in report.analysis_target["file"].items()
                if isinstance(v, (str, unicode, int, float))}
            self.report_info["file"]["task_id"] = analysis_id
        else:
            self.report_info["url"] = {"url": report.analysis_target["url"]}
            self.report_info["url"]["task_id"] = analysis_id

        self.report_info["analysis_id"] = report.analysis_id
        self.report_info["analysis_path"] = report.analysis_info["analysis_path"]
        self.report = report

    def include_config(self):
        """Reads config files and includes them in the
        current feedback object. Respects privacy by blanking
        out passwords and other sensitive information.
        """
        data = {}

        # iterate config files
        for cfg_path in glob(cwd("conf", "*.conf")):
            cfg_basename = os.path.basename(cfg_path)
            cfg_name = os.path.splitext(cfg_basename)[0]

            # read config, fetch sections
            cfg = Config(cfg_name)
            data[cfg_name] = cfg.to_dict()

        self.cfg = data

    def include_analysis(self, include_memdump=False):
        if not self.report.src:
            raise CuckooFeedbackError(
                "Report must first be included in order to include the analysis")
        analysis_path = self.report.analysis_info["analysis_path"]
        taken_dirs, taken_files = ExportController.get_files(analysis_path)

        if not include_memdump:
            taken_dirs = [z for z in taken_dirs if z[0] != "memory"]

        export = ExportController.create(task_id=self.report.analysis_id,
                                         taken_dirs=taken_dirs,
                                         taken_files=taken_files)
        export.seek(0)
        self.export = base64.b64encode(export.read())

    @staticmethod
    def already_submitted(analysis_id):
        report = AbstractReport(analysis_id=analysis_id)
        if report.analysis_feedback:
            return True

    def add_error(self, error):
        self.errors.append(error)

    def validate(self):
        if not self.contact["email"]:
            return
        if not self.message:
            return

        return True

    def to_dict(self):
        data = {
            "errors": self.errors,
            "contact": self.contact,
            "automated": self.was_automated,
            "message": self.message,
            "cuckoo": {
                "cuckoo_cwd": "",
                "cuckoo_app": ""
            }
        }

        if self.report:
            data["analysis_info"] = self.report_info

        if self.export:
            data["export"] = self.export

        if self.cfg:
            data["cfg"] = self.cfg

        return data
