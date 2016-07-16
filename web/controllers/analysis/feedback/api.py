# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from controllers.analysis.feedback.feedback import AnalysisFeedBackController

class FeedbackApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def send(request):
        if not request.is_ajax():
            return JsonResponse({"status": False, "message": "request not ajax"}, status=200)

        body = json.loads(request.body)

        task_id = body.get("task_id", None)
        email = body.get("email", "")
        message = body.get("message", "")
        company = body.get("company", "")

        include_analysis = body.get("include_analysis", False)
        include_memdump = body.get("include_memdump", False)

        if not task_id or not isinstance(task_id, int):
            return JsonResponse({"status": False, "message": "invalid task_id"}, status=200)

        for required in ["email", "message"]:
            if not required in body or len(body[required]) <= 5:
                return JsonResponse({"status": False, "message": "%s is required" % required}, status=200)

        feedback = AnalysisFeedBackController(task_id)
        feedback.email = email
        feedback.message = message
        feedback.company = company
        feedback.include_analysis = include_analysis
        feedback.include_memdump = include_memdump

        try:
            identifier = feedback.send()
        except Exception as e:
            return JsonResponse({"status": False, "message": str(e)}, status=200)

        return JsonResponse({"status": True, "feedback_id": identifier}, safe=False)
