# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json

from django.http import JsonResponse

from bin.utils import api_post
from controllers.analysis.feedback.feedback import AnalysisFeedBackController

class FeedbackApi:
    @api_post
    def send(request):
        if not request.is_ajax():
            return JsonResponse({"status": False, "message": "request not ajax"}, status=200)

        body = json.loads(request.body)

        task_id = body.get("task_id", None)
        firstname = body.get("firstname", "")
        email = body.get("email", "")
        message = body.get("message", "")
        company = body.get("company", "")

        include_analysis = body.get("include_analysis", False)
        include_memdump = body.get("include_memdump", False)

        if not task_id or not isinstance(task_id, int):
            return JsonResponse({"status": False, "message": "invalid task_id"}, status=200)

        for required in ["email", "message"]:
            if required not in body or len(body[required]) <= 5:
                return JsonResponse({"status": False, "message": "%s is required" % required}, status=200)

        feedback = AnalysisFeedBackController(task_id)
        feedback.email = email
        feedback.message = message
        feedback.company = company
        feedback.name = firstname
        feedback.include_analysis = include_analysis
        feedback.include_memdump = include_memdump

        try:
            identifier = feedback.send()
        except Exception as e:
            return JsonResponse({"status": False, "message": str(e)}, status=200)

        return JsonResponse({"status": True, "feedback_id": identifier}, safe=False)
