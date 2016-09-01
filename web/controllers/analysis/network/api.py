# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import base64

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from controllers.analysis.analysis import AnalysisController

class AnalysisNetworkApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def http_response_data(request):
        if not request.is_ajax():
            return JsonResponse({'status': False}, status=200)

        body = json.loads(request.body)

        task_id = body.get("task_id", None)
        request_body = body.get("request_body", False)
        request_index = body.get("request_index", None)

        if not task_id or not isinstance(request_index, int):
            return JsonResponse({"status": False, "message": "missing task_id or valid request_index"}, status=200)

        try:
            report = AnalysisController.get_report(task_id)

            if request_body:
                # @TO-DO: parse raw http request data, filter out body
                body = report["analysis"]["network"]["http"][request_index]["data"]
            else:
                body = report["analysis"]["network"]["http_ex"][request_index]["path"]


            body = open(body, "rb").read()
            body = base64.b64encode(body)

            return JsonResponse({
                "body": body
            }, safe=False)
        except:
            return JsonResponse({"status": False, "message": "error"}, status=200)
