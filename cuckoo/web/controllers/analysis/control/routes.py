# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.http import Http404, HttpResponseRedirect

from cuckoo.common.config import config
from cuckoo.core.database import Database
from cuckoo.web.utils import render_template

db = Database()

class AnalysisControlRoutes(object):
    @staticmethod
    def player(request, task_id):
        task = db.view_task(task_id)
        if not task:
            raise Http404("Task not found!")

        if not config("cuckoo:remotecontrol:enabled"):
            raise Http404(
                "Remote control is not enabled in the configuration! "
                "Please check our documentation on configuring Guacamole."
            )

        if task.options.get("remotecontrol") != "yes":
            raise Http404("Remote control was not enabled for this task.")

        if task.status == "reported":
            return HttpResponseRedirect("/analysis/%d/summary" % int(task_id))

        if task.status not in ("running", "completed"):
            raise Http404("task is not running")

        request.extra_scripts = ["guac.js"]
        return render_template(request, "rdp/index.html", task=task)
