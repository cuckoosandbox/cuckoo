# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from django.conf import settings
from django.shortcuts import render

from cuckoo.core.rooter import vpns
from cuckoo.common.config import Config
from cuckoo.core.database import Database
from cuckoo.misc import cwd

from controllers.submission.submission import SubmissionController

cfg = Config("routing")
results_db = settings.MONGO

class SubmissionRoutes:
    @staticmethod
    def index(request, kwargs={}):
        files = os.listdir(cwd("analyzer", "windows", "modules", "packages"))

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
        return render(request, "submission/test.html", values)

    @staticmethod
    def presubmit(request, submit_id):
        file_data = SubmissionController(submit_id=submit_id).get_submit()

        return render(request, "submission/index.html", {"file_data": file_data, "submit_id": submit_id})
        # return JsonResponse({"data": file_list}, encoder=json_default_response)
