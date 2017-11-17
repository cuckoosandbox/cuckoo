# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from django.http import HttpResponse
from django.shortcuts import redirect
from django.core.urlresolvers import reverse

from cuckoo.core.database import Database
from cuckoo.web.controllers.analysis.export.export import ExportController
from cuckoo.web.controllers.analysis.analysis import AnalysisController
from cuckoo.web.utils import view_error, render_template

class AnalysisRoutes:
    @staticmethod
    def recent(request):
        return render_template(request, "analysis/index.html")

    @staticmethod
    def detail(request, task_id, page):
        report = AnalysisController.get_report(task_id)

        pages = {
            "summary": "summary/index",
            "static": "static/index",
            "extracted": "extracted/index",
            "behavior": "behavior/index",
            "network": "network/index",
            "misp": "misp/index",
            "dropped_files": "dropped/dropped_files",
            "dropped_buffers": "dropped/dropped_buffers",
            "memory": "memory/index",
            "procmemory": "procmemory/index",
            "options": "options/index",
            "feedback": "feedback/index"
        }

        if page in pages.keys():
            return render_template(
                request, "analysis/pages/%s.html" % pages[page],
                report=report, page=page
            )
        else:
            return view_error(
                request, msg="Analysis subpage not found", status=404
            )

    @staticmethod
    def redirect_default(request, task_id):
        if not isinstance(task_id, (unicode, str)):
            task_id = str(task_id)

        return redirect(reverse(
            "analysis",
            args=(re.sub(r"\^d+", "", task_id), "summary")),
            permanent=False
        )

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
        return render_template(request, "analysis/export.html",
                               report=report, dirs=dirs, files=files)

    @staticmethod
    def reboot(request, task_id):
        task_obj = Database().add_reboot(task_id=task_id)
        return render_template(request, "submission/reboot.html",
                               task_id=task_id, task_obj=task_obj,
                               baseurl=request.build_absolute_uri("/")[:-1])
