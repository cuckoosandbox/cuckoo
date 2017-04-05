# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import json
import logging
import os
import requests
import traceback
import zipfile

from django.core.validators import validate_email, ValidationError
from django.http import Http404
from django.template import TemplateSyntaxError, TemplateDoesNotExist

from cuckoo.common.config import Config, config
from cuckoo.common.exceptions import CuckooFeedbackError
from cuckoo.core.report import Report
from cuckoo.misc import version, cwd
from cuckoo.web.controllers.analysis.analysis import AnalysisController

log = logging.getLogger(__name__)

class CuckooFeedback(object):
    """Contacts Cuckoo HQ with feedback & optional analysis dump."""
    endpoint = "https://feedback.cuckoosandbox.org/api/submit/"
    exc_whitelist = (
        CuckooFeedbackError,
    )
    exc_django = (
        TemplateDoesNotExist, TemplateSyntaxError
    )

    def enabled(self):
        return config("cuckoo:feedback:enabled")

    def send_exception(self, exception, request):
        """
        To be used during exception handling.
        @param exception: The exception class
        @param request: Django request object
        @return:
        """
        if not self.enabled():
            return

        feedback = CuckooFeedbackObject(
            automated=True, message="Exception encountered: %s" % exception
        )

        if isinstance(exception, self.exc_whitelist):
            log.debug("A whitelisted exception occurred: %s", exception)
            return

        # Ignore 404 exceptions regarding ".map" development files.
        if isinstance(exception, Http404) and ".map" in exception.message:
            return

        if isinstance(exception, self.exc_django):
            feedback.add_error(
                "A Django-related exception occurred: %s" % exception
            )

        feedback.add_traceback()

        class options(object):
            analysis = False
            json_report = False
            memdump = False
            config = True

        if request:
            if hasattr(request, "resolver_match") and request.resolver_match:
                if request.method == "POST" and request.is_ajax():
                    kwargs = json.loads(request.body)
                else:
                    kwargs = request.resolver_match.kwargs
            elif request.method == "GET":
                kwargs = request.GET
            elif request.method == "POST":
                kwargs = request.POST
            else:
                kwargs = {}

            task_id = (
                kwargs.get("task_id", kwargs.get("analysis_id"))
            )

            if task_id:
                options.analysis = True
                options.json_report = True

        if options.json_report:
            feedback.include_report_web(task_id)

        if feedback.report and options.analysis:
            feedback.include_analysis(memdump=options.memdump)

        return self.send_feedback(feedback)

    def send_form(self, task_id=None, name=None, email=None, message=None,
                  company=None, json_report=False, memdump=False):
        feedback = CuckooFeedbackObject(
            name=name, company=company, email=email,
            message=message, automated=False
        )

        if json_report:
            if not task_id or not isinstance(task_id, int):
                raise CuckooFeedbackError(
                    "An incorrect Task ID has been provided: %s!" % task_id
                )

            feedback.include_report_web(task_id)
            feedback.include_analysis(memdump=memdump)

        return self.send_feedback(feedback)

    def send_feedback(self, feedback):
        try:
            feedback.validate()
        except CuckooFeedbackError as e:
            raise CuckooFeedbackError(
                "Could not validate feedback object: %s" % e
            )

        headers = {
            "Accept": "application/json",
            "User-Agent": "Cuckoo %s" % version
        }

        try:
            r = requests.post(
                self.endpoint,
                data={
                    "feedback": json.dumps(feedback.to_dict()),
                },
                files=feedback.to_files(),
                headers=headers
            )
            r.raise_for_status()

            obj = r.json()
            if not obj.get("status"):
                raise CuckooFeedbackError(obj["message"])
            return obj["feedback_id"]
        except requests.RequestException as e:
            raise CuckooFeedbackError(
                "Invalid response from Cuckoo feedback server: %s" % e
            )
        except CuckooFeedbackError as e:
            raise CuckooFeedbackError(
                "Cuckoo feedback error while trying to send: %s" % e
            )

class CuckooFeedbackObject(object):
    """Feedback object."""
    export_files = [
        "analysis.log",
        "cuckoo.log",
        "dump.pcap",
        "tlsmaster.txt",
        ("logs", ".bson"),
        ("shots", ".jpg"),
    ]

    def __init__(self, message=None, email=None, name=None, company=None,
                 automated=False):
        self.automated = automated
        self.message = message
        self.contact = {
            "name": name or config("cuckoo:feedback:name"),
            "company": company or config("cuckoo:feedback:company"),
            "email": email or config("cuckoo:feedback:email"),
        }
        self.errors = []
        self.traceback = None
        self.export = []
        self.info = {}
        self.report = None

    def include_report(self, report):
        # Any and all errors.
        for error in report.errors:
            self.add_error(error)

        # Analysis information.
        if report.target["category"] == "file":
            self.info["file"] = report.target["file"]
        elif report.target["category"] == "url":
            self.info["url"] = report.target["url"]

        self.info["category"] = report.target["category"]
        self.report = report

    def include_report_web(self, task_id):
        try:
            report = Report(AnalysisController.get_report(task_id)["analysis"])
        except Http404:
            # No report available so ignoring the rest of this function.
            return

        return self.include_report(report)

    def gather_export_files(self, dirpath):
        """Returns a list of all files of interest from an analysis."""
        ret = []
        for name in self.export_files:
            if isinstance(name, basestring):
                filepath = os.path.join(dirpath, name)
                if os.path.isfile(filepath):
                    ret.append((name, filepath))
                continue

            if isinstance(name, tuple):
                dirname, ext = name
                dirpath = os.path.join(dirpath, dirname)
                if os.path.isdir(dirpath):
                    for filename in os.listdir(dirpath):
                        if not filename.endswith(ext):
                            continue

                        filepath = os.path.join(dirpath, filename)
                        if not os.path.isfile(filepath):
                            continue

                        filename = "%s/%s" % (dirname, filename)
                        ret.append((filename, filepath))
                continue

            raise RuntimeError(
                "Unknown export file defined: %s!" % name
            )
        self.export = ret

    def include_analysis(self, memdump=False):
        if not self.report:
            raise CuckooFeedbackError(
                "Report must be included first when including the analysis."
            )

        if "analysis_path" not in self.report.info:
            raise CuckooFeedbackError(
                "Can't include the entire analysis for this analysis as the "
                "analysis path isn't known."
            )

        if not os.path.isdir(self.report.info["analysis_path"]):
            raise CuckooFeedbackError(
                "Can't include the entire analysis for this analysis as the "
                "analysis path doesn't exist."
            )

        # TODO Support for also including memory dumps (should we?) and/or
        # behavioral logs or at least something like matched signatures.
        self.gather_export_files(self.report.info["analysis_path"])

    def add_error(self, error):
        self.errors.append(error)

    def add_traceback(self, tb=None):
        self.traceback = tb or traceback.format_exc()

    def validate(self):
        if not self.contact.get("name"):
            raise CuckooFeedbackError("Missing contact name")

        if not self.contact.get("email"):
            raise CuckooFeedbackError("Missing contact email")

        try:
            validate_email(self.contact["email"])
        except ValidationError:
            raise CuckooFeedbackError(
                "Invalid email address: %s!" % self.contact["email"]
            )

        if not self.message:
            raise CuckooFeedbackError("Missing feedback message")

        return True

    def to_dict(self):
        return {
            "version": version,
            "errors": self.errors,
            "traceback": self.traceback,
            "contact": self.contact,
            "automated": self.automated,
            "message": self.message,
            "info": self.info,
            "cuckoo": {
                "cwd": cwd(),
                "app": os.environ.get("CUCKOO_APP"),
                "config": Config.from_confdir(cwd("conf"), sanitize=True),
            },
        }

    def to_files(self):
        buf = io.BytesIO()
        z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
        for filename, filepath in self.export:
            z.write(filepath, filename)
        z.close()
        buf.seek(0)
        return {
            "file": buf,
        }
