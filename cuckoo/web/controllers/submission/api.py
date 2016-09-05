# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect

from cuckoo.common.files import Folders, Files, Storage
from cuckoo.core.database import Database
from controllers.submission.submission import SubmissionController

from bin.utils import api_post, json_default_response

results_db = settings.MONGO

class SubmissionApi:
    @api_post
    def submit(request, body):
        dirpath = Folders.create_temp()

        for f in request.FILES.getlist("files[]"):
            filename = Storage.get_filename_from_path(f.name)
            Files.create(dirpath, filename, f.file)

        submit_id = Database().add_submit(dirpath)
        return redirect('submission/pre', submit_id=submit_id)

    @api_post
    def filetree(request, body):
        submit_id = body.get("submit_id", 0)

        controller = SubmissionController(submit_id=submit_id)
        data = controller.get_filetree()

        return JsonResponse({"status": "OK", "data": data}, encoder=json_default_response)
