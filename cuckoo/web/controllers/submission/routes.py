# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.core.rooter import vpns
from cuckoo.common.config import Config
from cuckoo.core.database import Database, Submit
from cuckoo.misc import cwd
from cuckoo.web.bin.utils import view_error, render_template

cfg = Config("routing")
db = Database()

class SubmissionRoutes:
    @staticmethod
    def submit(request):
        return render_template(request, "submission/submit.html")

    @staticmethod
    def postsubmit(request):
        submit_ids = request.GET.getlist("id")
        if not submit_ids:
            return view_error(request, "No task ids specified")

        return render_template(request, "submission/postsubmit.html", submit_ids=submit_ids)

    @staticmethod
    def presubmit(request, submit_id):
        session = db.Session()
        submit = session.query(Submit).filter(Submit.id == submit_id).first()
        if not submit:
            return render_template(request, "submission/presubmit.html", data={})

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

        data = {
            "packages": sorted(packages),
            "machines": machines,
            "vpns": vpns.values(),
            "route": cfg.routing.route,
            "internet": cfg.routing.internet,
            "submit_id": submit_id,
            "submit": submit
        }

        return render_template(request, "submission/presubmit.html", **data)
