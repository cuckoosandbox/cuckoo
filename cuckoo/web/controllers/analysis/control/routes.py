# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from cuckoo.core.database import Database
from cuckoo.web.utils import view_error, render_template
from django.http import Http404

db = Database()


class AnalysisControlRoutes:
    @staticmethod
    def player(request, task_id):
        try:
            task = db.view_task(task_id)
            if not task:
                raise Http404("task not found")

            if task.options.get("remotecontrol") != "yes":
                raise Http404("remote control was not enabled for this task")

            data = {
                "task": task,
            }
            return render_template(request, "analysis/pages/control/player.html", **data)
        except Exception as e:
            return view_error(request, str(e))
