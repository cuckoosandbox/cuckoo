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
from controllers.submission.submission import SubmissionController

from bin.utils import json_default_response


results_db = settings.MONGO

class SubmissionApi:
    @api_post
    def submit(request, body):
        data = []
        for file in request.FILES.getlist("files[]"):
            data.append({"data": file.file, "name": file.name})

        tmp_path = Files.tmp_put(files=data)

        db = Database()
        submit_id = db.add_submit(tmp_path)

        return redirect('submission/pre', submit_id=submit_id)

    @api_post
    def filetree(request, body):
        submit_id = body.get("submit_id", 0)

        controller = SubmissionController(submit_id=submit_id)
        data = controller.get_filetree()

        return JsonResponse({"status": "OK", "data": data}, encoder=json_default_response)
