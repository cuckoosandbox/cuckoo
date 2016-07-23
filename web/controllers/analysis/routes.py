# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse

from lib.cuckoo.core.database import Database, TASK_PENDING

from controllers.analysis.export.export import ExportController
from controllers.analysis.analysis import AnalysisController
from bin.utils import view_error

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
    def detail(request, task_id, page):
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
            "options": "options/index",
            "feedback": "feedback/index"
        }

        if page in pages.keys():
            return render(request, "analysis/pages/%s.html" % pages[page], {'report': report,
                                                                            'page': page})

    @staticmethod
    def redirect_default(request, task_id):
        if not isinstance(task_id, (unicode, str)):
            task_id = str(task_id)

        return redirect(reverse('analysis', args=(re.sub(r'\^d+', '', task_id), "summary",)), permanent=False)

    @staticmethod
    def export(request, task_id):
        if request.method == "POST":
            taken_dirs = request.POST.getlist("dirs")
            taken_files = request.POST.getlist("files")

            try:
                zip = ExportController.create(task_id=task_id,
                                              taken_dirs=taken_dirs,
                                              taken_files=taken_files)

                response = HttpResponse(zip.getvalue(), content_type="application/zip")
                response["Content-Disposition"] = "attachment; filename=%s.zip" % task_id
                return response

            except Exception as e:
                return view_error(request, str(e))

        report = AnalysisController.get_report(task_id)

        if "analysis_path" not in report.get("analysis", {}).get("info", {}):
            return view_error(request, "The analysis was created before the export "
                                       "functionality was integrated with Cuckoo and is "
                                       "therefore not available for this task (in order to "
                                       "export this analysis, please reprocess its report).")

        analysis_path = report["analysis"]["info"]["analysis_path"]
        dirs, files = ExportController.get_files(analysis_path)

        return render(request, "analysis/export.html", {
            "report": report,
            "dirs": dirs,
            "files": files,
        })


    @staticmethod
    def reboot(request, task_id):
        task_obj = Database().add_reboot(task_id=task_id)

        return render(request, "submission/reboot.html", {
            "task_id": task_id,
            "task_obj": task_obj,
            "baseurl": request.build_absolute_uri("/")[:-1],
        })
