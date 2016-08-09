# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from lib.cuckoo.core.rooter import vpns
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from controllers.submission.submission import SubmissionController
from bin.utils import json_default_response

cfg = Config()
results_db = settings.MONGO

class SubmissionRoutes:
    @staticmethod
    def index(request, kwargs={}):
        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        # Prepare a list of VM names, description label based on tags.
        machines = []
        for machine in Database().list_machines():
            tags = []
            for tag in machine.tags:
                tags.append(tag.name)

            if tags:
                label = machine.label + ": " + ", ".join(tags)
            else:
                label = machine.label

            machines.append((machine.label, label))

        # Prepend ALL/ANY options.
        machines.insert(0, ("", "First available"))
        machines.insert(1, ("all", "All"))

        values = {
            "packages": sorted(packages),
            "machines": machines,
            "vpns": vpns.values(),
            "route": cfg.routing.route,
            "internet": cfg.routing.internet,
        }

        values.update(kwargs)
        return render(request, "submission/index.html", values)

    @staticmethod
    @csrf_exempt
    @require_http_methods(["POST"])
    def presubmit(request):
        data = {}

        for file in request.FILES.getlist("sample"):
            extracted = SubmissionController().presubmit(file.name, file.file.read())

            if isinstance(extracted, dict):
                data[extracted["file"].hash] = extracted
            else:
                data[extracted.hash] = {"file": extracted}

        return JsonResponse({"data": data}, encoder=json_default_response)