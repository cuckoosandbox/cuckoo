# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path

from django.shortcuts import redirect

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.web.utils import view_error, render_template, dropped_filepath

log = logging.getLogger(__name__)
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
        if not filepath:
            return view_error(request, "No such dropped file was found!")

        # TODO Obtain the original name for this file.
        submit_id = submit_manager.pre("files", [{
            "name": os.path.basename(filepath),
            "data": open(filepath, "rb"),
        }])

        return redirect("submission/pre", submit_id=submit_id)

    @staticmethod
    def resubmit(request, task_id):
        task = Database().view_task(task_id)
        if not task:
            return view_error(request, "No Task was found with this ID")

        if task.category == "url":
            # TODO This most certainly needs to be improved.
            submit_id = submit_manager.pre("strings", [
                task.target,
            ], submit_manager.translate_options_to(task.options))
        else:
            if not os.path.exists(task.target):
                return view_error(
                    request, "The file you're trying to resubmit "
                    "no longer exists. Please resubmit it altogether!"
                )

            # TODO There's a very good chance this won't work properly for
            # analyses of type "archive".
            submit_id = submit_manager.pre("files", [{
                "name": os.path.basename(task.target),
                "data": open(task.target, "rb"),
            }], submit_manager.translate_options_to(task.options))

        return redirect("submission/pre", submit_id=submit_id)

    @staticmethod
    def reboot(request, task_id):
        # TODO Dummy usage, should probably be improved.
        submit_id = Database().add_submit(None, None, None)

        task_id = Database().add_reboot(task_id=task_id, submit_id=submit_id)
        if not task_id:
            return view_error(request, "Error adding reboot analysis!")

        return redirect("submission/post", submit_id=submit_id)

    @staticmethod
    def import_(request):
        if request.method == "GET":
            return render_template(request, "analysis/import.html")

        if request.method != "POST":
            return view_error(request, "Import analysis request must be POST!")

        submit_id = Database().add_submit(None, None, None)
        task_ids = []

        for analysis in request.FILES.values():
            if not analysis.size:
                continue

            try:
                task_ids.append(submit_manager.import_(analysis, submit_id))
            except CuckooOperationalError as e:
                log.warning(
                    "Error importing analysis (%s): %s", analysis.name, e
                )
                continue

        return redirect("submission/post", submit_id=submit_id)
