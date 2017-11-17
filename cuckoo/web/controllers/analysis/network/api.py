# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64

from django.http import JsonResponse

from cuckoo.web.controllers.analysis.analysis import AnalysisController
from cuckoo.web.utils import api_post, json_error_response

class AnalysisNetworkApi:
    @staticmethod
    def _request_response(report, protocol, request_index):
        network = report["analysis"]["network"]["%s_ex" % protocol][request_index]
        request = response = ""
        if "req" in network and "resp" in network:
            if network["req"].get("path"):
                request = open(network["req"]["path"], "rb").read()
            if network["resp"].get("path"):
                response = open(network["resp"]["path"], "rb").read()
        elif "path" in network:
            request = open(network["path"], "rb").read()
        return base64.b64encode(request), base64.b64encode(response)

    @api_post
    def http_data(request, body):
        task_id = body.get("task_id", None)
        request_body = body.get("request_body", False)
        protocol = body.get("protocol", None)
        request_index = body.get("request_index", None)

        if not task_id or not isinstance(request_index, int):
            return json_error_response(
                "missing task_id or valid request_index"
            )

        report = AnalysisController.get_report(task_id)

        if request_body:
            # @TO-DO: parse raw http request data, filter out body
            req = ""
            resp = report["analysis"]["network"]["http"][request_index]["data"]
        else:
            req, resp = AnalysisNetworkApi._request_response(
                report, protocol, request_index
            )

        return JsonResponse({
            "request": req,
            "response": resp,
        }, safe=False)
