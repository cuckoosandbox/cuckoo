# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from django.http import JsonResponse, HttpResponse
from wsgiref.util import FileWrapper

from cuckoo.core.database import Database
from cuckoo.misc import cwd

from cuckoo.web.utils import json_error_response, json_fatal_response, api_get

db = Database()

class FilesApi:
    @api_get
    def view(request, md5=None, sha256=None, sample_id=None):
        data = {}

        if md5:
            sample = db.find_sample(md5=md5)
        elif sha256:
            sample = db.find_sample(sha256=sha256)
        elif sample_id:
            sample = db.view_sample(sample_id)
        else:
            return json_fatal_response("Invalid lookup term")

        if not sample:
            return json_error_response("File not found")

        data["sample"] = sample.to_dict()
        return JsonResponse({"status": True, "data": data})

    @api_get
    def get(request, sha256):
        filepath = cwd("storage", "binaries", sha256)
        if os.path.exists(filepath):
            return json_error_response("File not found")

        return HttpResponse(
            FileWrapper(open(filepath, "rb")),
            content_type="application/octet-stream; charset=UTF-8"
        )
