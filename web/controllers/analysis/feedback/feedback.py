# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import json
import requests

from controllers.analysis.analysis import AnalysisController
from controllers.analysis.export.export import ExportController

class AnalysisFeedBackController(object):
    """Contacts Cuckoo HQ with feedback + optional analysis dump"""

    def __init__(self, task_id):
        self._url_feedback = "http://cuckoo.sh/test/"

        self.task_id = task_id
        self.email = None
        self.message = None
        self.include_analysis = False
        self.include_memdump = False

    def send(self):
        data = {}

        report = AnalysisController.get_report(self.task_id)
        analysis_path = report["analysis"]["info"]["analysis_path"]
        taken_dirs, taken_files = ExportController.get_files(analysis_path)

        export = ExportController.create(task_id=self.task_id,
                                         taken_dirs=taken_dirs,
                                         taken_files=taken_files)

        # attach the zip file
        data["export"] = export

        # attach additional analysis information
        data["info"]["analysis_id"] = self.task_id
        if "file" in report["analysis"]["target"]:
            data["info"] = {k: v for k, v in report["analysis"]["target"]["file"].items() if
                            isinstance(v, (str, unicode, int, float))}
        else:
            data["info"] = {
                "url": report["analysis"]["target"]["url"]  # @TO-DO: test this
            }

        # attach feedback message & contact email
        data["contact"] = {
            "email": self.email,
            "message": self.message
        }

        resp = requests.post(url=self._url_feedback, data=data)
        if not resp.status_code == 200:
            raise Exception("the remote server did not respond correctly")

        try:
            return json.loads(resp.content)
        except Exception as e:
            raise Exception("could not parse server response as JSON: %s" % str(e))
