# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.shortcuts import redirect

from cuckoo.core.database import Database, Submit
from cuckoo.web.bin.utils import view_error, render_template

class SubmissionRoutes(object):
    @staticmethod
    def submit(request):
        return render_template(request, "submission/submit.html")

    @staticmethod
    def postsubmit(request):
        task_ids = request.GET.getlist("id")
        if not task_ids:
            return view_error(request, "No task ids specified")

        return render_template(
            request, "submission/postsubmit.html", task_ids=task_ids
        )

    @staticmethod
    def presubmit(request, submit_id):
        session = Database().Session()
        submit = session.query(Submit).get(submit_id)
        if not submit:
            # TODO Include an error message regarding the invalid Submit entry.
            return redirect("submission/index")

        return render_template(
            request, "submission/presubmit.html", submit_id=submit_id
        )
