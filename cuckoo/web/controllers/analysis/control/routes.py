# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from cuckoo.web.controllers.analysis.control.control import (
    AnalysisControlController
)
from cuckoo.web.utils import view_error, render_template


class AnalysisControlRoutes:
    @staticmethod
    def player(request, task_id):
        try:
            data = {"task_id": task_id}
            return render_template(request, "analysis/pages/control/player.html", **data)
        except Exception as e:
            return view_error(request, str(e))