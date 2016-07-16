# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import json
import requests
from datetime import datetime

from django.conf import settings

from controllers.analysis.analysis import AnalysisController
from controllers.analysis.export.export import ExportController

results_db = settings.MONGO

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
        data = {
            "info": {
                "analysis_id": self.task_id
            }
        }

        report = AnalysisController.get_report(self.task_id)
        if 'feedback' in report['analysis'] and isinstance(report['analysis']['feedback'], dict):
            raise Exception('Feedback previously sent')

        if self.include_analysis:
            analysis_path = report["analysis"]["info"]["analysis_path"]
            taken_dirs, taken_files = ExportController.get_files(analysis_path)

            if not self.include_memdump:
                taken_dirs = [z for z in taken_dirs if z[0] != "memory"]

            export = ExportController.create(task_id=self.task_id,
                                             taken_dirs=taken_dirs,
                                             taken_files=taken_files)

            # attach the zip file
            data["export"] = export

        # attach additional analysis information
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
            resp = json.loads(resp.content)
            self._register()

            return resp['identifier']
        except ValueError:
            raise Exception("could not parse server response as JSON")

    def _register(self):
        return results_db.analysis.update_one(
            {"info.id": int(self.task_id)},
            {"$set": {"feedback": self.to_dict()}})

    def to_dict(self):
        return {
            "email": self.email,
            "message": self.message,
            "include_memdump": self.include_memdump,
            "include_analysis": self.include_analysis,
            "date": datetime.now()
        }