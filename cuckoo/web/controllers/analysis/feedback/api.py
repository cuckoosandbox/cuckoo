# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.http import JsonResponse

from bin.utils import api_post, json_error_response
from controllers.analysis.feedback.feedback import AnalysisFeedBackController

class FeedbackApi:
    @api_post
    def send(request, body):
        task_id = body.get("task_id", None)
        firstname = body.get("firstname", "")
        email = body.get("email", "")
        message = body.get("message", "")
        company = body.get("company", "")

        include_analysis = body.get("include_analysis", False)
        include_memdump = body.get("include_memdump", False)

        if not task_id or not isinstance(task_id, int):
            return json_error_response("Invalid task_id")
        if "email" not in body:
            return json_error_response("Email is required")
        if "message" not in body or len(body["message"]) <= 14:
            return json_error_response("Message not present or too short")

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
            return json_error_response(str(e))

        return JsonResponse({"status": True, "feedback_id": identifier}, safe=False)
