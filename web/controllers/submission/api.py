# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from lib.cuckoo.common.files import Files
from lib.cuckoo.core.database import Database
from controllers.submission.submission import SubmissionController

from bin.utils import json_default_response, api_post

results_db = settings.MONGO

class SubmissionApi:
    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def presubmit(request):
        data = []
        for file in request.FILES.getlist("files[]"):
            data.append({"data": file.file, "name": file.name})

        tmp_path = Files.tmp_put(files=data)

        db = Database()
        submit_id = db.add_submit(tmp_path)

        return redirect('submission/pre', submit_id=submit_id)

    @api_post
    def submit(request, body):
        if "selected_files" not in body or "form" not in body or "submit_id" not in body:
            return JsonResponse({
                "status": False, "message": "Bad parameters"},
                encoder=json_default_response)
        
        data = {
            "selected_files": body["selected_files"],
            "form": {
                "_checkboxes": {}
            }
        }
        
        for option in ["route", "package", "timeout", "options", "priority", "custom", "tags"]:
            if option not in body["form"]:
                return JsonResponse({
                    "status": False,
                    "message": "Expected %s in parameter \"form\", none found" % option},
                    encoder=json_default_response)
            else:
                val = body["form"][option].lower()
                if val == "none" or val == "":
                    body["form"][option] = None

                data["form"][option] = body["form"][option]

        cbs = data["form"]["_checkboxes"]
        for checkbox_option in ["free", "process_memory", "memory", "enforce_timeout", "human", "services"]:
            if checkbox_option not in body["form"]:
                cbs[checkbox_option] = False
            else:
                if body["form"][checkbox_option] == "on":
                    cbs[checkbox_option] = True
                else:
                    cbs[checkbox_option] = False

        # do something with `data`
        controller = SubmissionController(submit_id=body["submit_id"])

        return JsonResponse({"status": True, "data": ""}, encoder=json_default_response)

    @api_post
    def filetree(request, body):
        submit_id = body.get("submit_id", 0)

        controller = SubmissionController(submit_id=submit_id)
        data = controller.get_filetree()

        return JsonResponse({"status": True, "data": data}, encoder=json_default_response)
