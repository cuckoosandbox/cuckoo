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

from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.web.bin.utils import api_post, JsonSerialize, json_error_response

results_db = settings.MONGO
db = Database()

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

            submit_id = SubmitManager().pre(submit_type="files", data=data)
            return redirect("submission/pre", submit_id=submit_id)
        else:
            body = json.loads(request.body)
            submit_type = body["type"]

            if submit_type != "strings":
                return json_error_response("type not \"strings\"")

            data = body["data"].split("\n")

            submit_id = SubmitManager().pre(submit_type=submit_type, data=data)

            return JsonResponse({
                "status": True,
                "submit_id": submit_id,
            }, encoder=JsonSerialize)

    @api_post
    def get_files(request, body):
        submit_id = body.get("submit_id", 0)
        password = body.get("password", None)
        astree = body.get("astree", True)

        controller = SubmitManager()

        data = controller.get_files(
            submit_id=submit_id,
            password=password,
            astree=astree
        )

        return JsonResponse({
            "status": True,
            "data": data,
        }, encoder=JsonSerialize)

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
            "custom", "tags", "machine", "human"
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

        controller = SubmitManager()
        options = data["form"].copy()
        selected_files= data["selected_files"]

        tasks = controller.submit(submit_id=body["submit_id"],
                                  selected_files=selected_files,
                                  **options)

        return JsonResponse({
            "status": True,
            "data": tasks,
        }, encoder=JsonSerialize)
