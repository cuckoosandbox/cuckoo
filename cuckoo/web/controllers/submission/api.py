# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from bin.utils import api_post, JsonSerialize, json_error_response
from controllers.submission.submission import SubmissionController

results_db = settings.MONGO

class SubmissionApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def presubmit(request):
        files = request.FILES.getlist("files[]")
        data = []

        if files:
            for f in files:
                data.append({
                    "name": f.name,
                    "data": f.file,
                })
            submit_type = "files"
        else:
            body = json.loads(request.body)
            submit_type = body["type"]

            if submit_type != "url" or "data" not in body:
                return json_error_response("type not \"url\"")

            data = body["data"].split("\n")

        if submit_type == "url" or submit_type == "files":
            submit_id = SubmissionController.presubmit(
                submit_type=submit_type, data=data
            )
            return redirect("submission/pre", submit_id=submit_id)

        return json_error_response("submit failed")

    @api_post
    def submit(request, body):
        if "selected_files" not in body or "form" not in body or \
                "submit_id" not in body:
            return json_error_response("Bad parameters")

        data = {
            "selected_files": body["selected_files"],
            "form": {},
        }

        options = (
            "route", "package", "timeout", "options", "priority",
            "custom", "tags",
        )

        for option in options:
            if option not in body["form"]:
                return json_error_response(
                    "Expected %s in parameter \"form\", none found" % option
                )

            val = body["form"][option].lower()
            if val == "none" or val == "":
                body["form"][option] = None

            data["form"][option] = body["form"][option]

        checkboxes = (
            "free", "process_memory", "memory", "enforce_timeout",
            "human", "services",
        )

        for checkbox in checkboxes:
            if checkbox not in body["form"]:
                data["form"][checkbox] = False
            else:
                if body["form"][checkbox] == "on":
                    data["form"][checkbox] = True
                else:
                    data["form"][checkbox] = False

        # do something with `data`
        controller = SubmissionController(submit_id=body["submit_id"])
        tasks = controller.submit(data)

        return JsonResponse({
            "status": True,
            "data": tasks,
        }, encoder=JsonSerialize)

    @api_post
    def filetree(request, body):
        submit_id = body.get("submit_id", 0)

        controller = SubmissionController(submit_id=submit_id)
        data = controller.get_files(astree=True)

        return JsonResponse({
            "status": True,
            "data": data,
        }, encoder=JsonSerialize)
