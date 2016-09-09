# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64

from django.http import JsonResponse

from bin.utils import api_post, json_error_response
from controllers.analysis.analysis import AnalysisController

class AnalysisNetworkApi:
    @api_post
    def http_response_data(request, body):
        task_id = body.get("task_id", None)
        request_body = body.get("request_body", False)
        request_index = body.get("request_index", None)

        if not task_id or not isinstance(request_index, int):
            return json_error_response("missing task_id or valid request_index")

        try:
            report = AnalysisController.get_report(task_id)

            if request_body:
                # @TO-DO: parse raw http request data, filter out body
                data = report["analysis"]["network"]["http"][request_index]["data"]
            else:
                data = report["analysis"]["network"]["http_ex"][request_index]["path"]

            data = base64.b64encode(open(data, "rb").read())

            return JsonResponse({
                "body": data
            }, safe=False)
        except:
            return json_error_response("error")
