# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from controllers.analysis.export.export import ExportController
from controllers.analysis.analysis import AnalysisController

class ExportApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def export_estimate_size(request):
        if not request.is_ajax():
            return JsonResponse({'status': False}, status=200)

        body = json.loads(request.body)

        task_id = body.get('task_id', None)
        taken_dirs = body.get("dirs", [])
        taken_files = body.get("files", [])

        if not taken_dirs and not taken_files:
            return JsonResponse({"size": 0, "size_human": "-"}, safe=False)

        if not task_id:
            raise Exception('invalid task_id')

        size = ExportController.estimate_size(task_id=task_id,
                                              taken_dirs=taken_dirs,
                                              taken_files=taken_files)

        return JsonResponse(size, safe=False)

    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def get_files(request):
        body = json.loads(request.body)

        task_id = body.get('task_id', None)

        if not task_id:
            raise Exception('invalid task_id')

        report = AnalysisController.get_report(task_id)
        analysis_path = report["analysis"]["info"]["analysis_path"]

        dirs, files = ExportController.get_files(analysis_path)

        return JsonResponse({"dirs": dirs, "files": files}, safe=False)
