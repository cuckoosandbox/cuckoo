# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import json
import logging
import os
import requests
import traceback

from cuckoo.misc import cwd
from django.core.validators import validate_email, ValidationError
from django.template import TemplateSyntaxError, TemplateDoesNotExist
from django.conf import settings
from django.http import Http404

from cuckoo.core.report import AbstractReport
from cuckoo.common.config import Config, config
from cuckoo.misc import version
from cuckoo.web.controllers.analysis.export.export import ExportController

from cuckoo.common.exceptions import CuckooFeedbackError

log = logging.getLogger(__name__)

class CuckooFeedback(object):
    """Contacts Cuckoo HQ with feedback + optional analysis dump"""

    def __init__(self):
        self.endpoint = "https://cuckoo.sh/feedback/api/submit/"
        self.mongo = settings.MONGO

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

        if request:
            if hasattr(request, "resolver_match") and request.resolver_match:
                if request.method == "POST" and request.is_ajax():
                    request_kwargs = json.loads(request.body)
                else:
                    request_kwargs = request.resolver_match.kwargs
            elif request.method == "GET":
                request_kwargs = request.GET
            elif request.method == "POST":
                request_kwargs = request.POST
            else:
                request_kwargs = None

            if request_kwargs:
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

        try:
            feedback.validate()
        except (CuckooFeedbackError, ValidationError) as ex:
            raise CuckooFeedbackError("Could not validate feedback object: %s" % str(ex))

        return self._send(feedback)

    def send(self, analysis_id=None, name="", email="", message="", company="",
             include_json_report=False, include_analysis=False,
             include_memdump=False, was_automated=False):
        if not config("cuckoo:feedback:enabled"):
            raise CuckooFeedbackError(
                "Feedback not enabled in config or feedback options missing"
            )

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

            feedback.include_report(analysis_id=analysis_id)

        if include_analysis:
            feedback.include_analysis(include_memdump=include_memdump)

        feedback_id = self._send(feedback)
        return feedback_id

    def _send(self, feedback):
        try:
            feedback.validate()
        except CuckooFeedbackError as ex:
            raise CuckooFeedbackError("Could not validate feedback object: %s" % str(ex))

        feedback = feedback.to_dict()
        headers = {
            "Content-type": "application/json",
            "Accept": "text/plain",
            "User-Agent": "Cuckoo %s" % version
        }

        try:
            resp = requests.post(
                url=self.endpoint,
                json=feedback,
                headers=headers
            )
            if not resp.status_code == 200:
                raise CuckooFeedbackError("the remote server did not respond correctly")

            resp = json.loads(resp.content)
            if "status" not in resp or not resp["status"]:
                raise CuckooFeedbackError(resp["message"])

            return resp["feedback_id"]
        except requests.exceptions.RequestException as e:
            msg = "Invalid response from Cuckoo feedback server: %s", str(e)
            log.error(msg)
            raise CuckooFeedbackError(msg)
        except CuckooFeedbackError as e:
            msg = "Cuckoo feedback error while sending: %s", str(e)
            log.error(msg)
            raise CuckooFeedbackError(msg)
        except Exception as e:
            msg = "Unknown feedback error while sending: %s" % str(e)
            log.error(msg)
            raise CuckooFeedbackError(msg)

class CuckooFeedbackObject:
    def __init__(self, message=None, email=None, name=None, company=None, was_automated=False):
        self.was_automated = was_automated
        self.message = message
        self.errors = []
        self.contact = {
            "name": config("cuckoo:feedback:name"),
            "company": config("cuckoo:feedback:company"),
            "email": config("cuckoo:feedback:email"),
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
                if isinstance(v, (str, unicode, int, float))
            }
            self.report_info["file"]["task_id"] = analysis_id
        else:
            self.report_info["url"] = {"url": report.analysis_target["url"]}
            self.report_info["url"]["task_id"] = analysis_id

        self.report_info["analysis_id"] = report.analysis_id
        self.report_info["analysis_path"] = report.analysis_info["analysis_path"]
        self.report = report

    def include_analysis(self, include_memdump=False):
        if not self.report.src:
            raise CuckooFeedbackError(
                "Report must first be included in order to include the analysis"
            )

        analysis_path = self.report.analysis_info["analysis_path"]
        taken_dirs, taken_files = ExportController.get_files(analysis_path)

        if not include_memdump:
            taken_dirs = [z for z in taken_dirs if z[0] != "memory"]

        export = ExportController.create(task_id=self.report.analysis_id,
                                         taken_dirs=taken_dirs,
                                         taken_files=taken_files,
                                         report=self.report.src)
        export.seek(0)
        self.export = base64.b64encode(export.read())

    def add_error(self, error):
        self.errors.append(error)

    def validate(self):
        for expect in ["email", "name"]:
            if expect not in self.contact or not self.contact[expect]:
                raise CuckooFeedbackError("Missing contact information: %s" % expect)

        validate_email(self.contact["email"])

        if not self.message:
            raise CuckooFeedbackError("Missing feedback message")

        return True

    def to_dict(self):
        data = {
            "errors": self.errors,
            "contact": self.contact,
            "automated": self.was_automated,
            "message": self.message,
            "cuckoo": {
                "cwd": cwd(),
                "app": os.environ.get("CUCKOO_APP"),
            }
        }

        if self.report:
            data["analysis_info"] = self.report_info

        if self.export:
            data["export"] = self.export

        data["cfg"] = Config.from_confdir(cwd("conf"), sanitize=True)

        return data
