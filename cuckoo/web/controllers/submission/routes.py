# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from django.shortcuts import redirect

from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.web.bin.utils import view_error, render_template, dropped_filepath

submit_manager = SubmitManager()

class SubmissionRoutes(object):
    @staticmethod
    def submit(request):
        return render_template(request, "submission/submit.html")

    @staticmethod
    def postsubmit(request, submit_id):
        submit = Database().view_submit(submit_id, tasks=True)
        if not submit:
            return view_error(request, "Invalid Submit ID specified")

        task_ids = []
        for task in submit.tasks:
            task_ids.append(task.id)

        if not task_ids:
            return view_error(
                request, "This Submit ID is not associated with any tasks. "
                "Please submit some files before loading this page."
            )

        return render_template(
            request, "submission/postsubmit.html", task_ids=sorted(task_ids)
        )

    @staticmethod
    def presubmit(request, submit_id):
        submit = Database().view_submit(submit_id)
        if not submit:
            # TODO Include an error message regarding the invalid Submit entry.
            return redirect("submission/index")

        return render_template(
            request, "submission/presubmit.html", submit_id=submit_id
        )

    @staticmethod
    def dropped(request, task_id, sha1):
        filepath = dropped_filepath(task_id, sha1)

        # TODO Obtain the original name for this file.
        submit_id = submit_manager.pre("files", [{
            "name": os.path.basename(filepath),
            "data": open(filepath, "rb"),
        }])

        return redirect("submission/pre", submit_id=submit_id)
