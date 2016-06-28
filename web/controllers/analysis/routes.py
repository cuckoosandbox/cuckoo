# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from django.conf import settings
from django.views.decorators.http import require_safe
from django.http import HttpResponse
from django.shortcuts import render, redirect
import pymongo

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_COMPLETED
from lib.cuckoo.common.utils import versiontuple
from lib.cuckoo.common.constants import LATEST_HTTPREPLAY
from controllers.analysis.analysis import AnalysisController
results_db = settings.MONGO


class AnalysisRoutes:
    @staticmethod
    def recent(request):
        db = Database()
        tasks_files = db.list_tasks(limit=50, category="file", not_status=TASK_PENDING)
        tasks_urls = db.list_tasks(limit=50, category="url", not_status=TASK_PENDING)

        analyses_files = []
        analyses_urls = []

        if tasks_files:
            for task in tasks_files:
                new = task.to_dict()
                new["sample"] = db.view_sample(new["sample_id"]).to_dict()

                filename = os.path.basename(new["target"])
                new.update({"filename": filename})

                if db.view_errors(task.id):
                    new["errors"] = True

                analyses_files.append(new)

        if tasks_urls:
            for task in tasks_urls:
                new = task.to_dict()

                if db.view_errors(task.id):
                    new["errors"] = True

                analyses_urls.append(new)

        return render(request, "analysis/index.html", {
            "files": analyses_files,
            "urls": analyses_urls,
        })

    @staticmethod
    def analysis(request, task_id, page):
        report = AnalysisController.get_report(task_id)

        pages = {
            "summary": "summary/index",
            "static": "static/index",
            "behavior": "behavior/index",
            "network": "network/index",
            "misp": "misp/index",
            "dropped_files": "dropped/dropped_files",
            "dropped_buffers": "dropped/dropped_buffers",
            "procmemory": "procmemory/index",
            "admin": "admin/index"
        }

        if page in pages.keys():
            return render(request, "analysis/pages/%s.html" % pages[page], {'report': report,
                                                                            'page': page})
    @staticmethod
    def export_analysis(request, task_id):
        if request.method == "POST":
            zip = AnalysisController.get_export(request, task_id)

            response = HttpResponse(zip.getvalue(), content_type="application/zip")
            response["Content-Disposition"] = "attachment; filename=%s.zip" % task_id
            return response

        report = AnalysisController.get_report(task_id)

        if "analysis_path" not in report.get("analysis", {}).get("info", {}):
            return render(request, "error.html", {
                "error": "The analysis was created before the export "
                         "functionality was integrated with Cuckoo and is "
                         "therefore not available for this task (in order to "
                         "export this analysis, please reprocess its report)."
            })

        analysis_path = report["analysis"]["info"]["analysis_path"]

        # Locate all directories/results available for this analysis.
        dirs, files = [], []
        for filename in os.listdir(analysis_path):
            path = os.path.join(analysis_path, filename)
            if os.path.isdir(path):
                dirs.append((filename, len(os.listdir(path))))
            else:
                files.append(filename)

        return render(request, "analysis/export.html", {
            "report": report,
            "dirs": dirs,
            "files": files,
        })
