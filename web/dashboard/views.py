# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import time

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe

sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING

@require_safe
def index(request):
    db = Database()

    report = dict(
        total_samples=db.count_samples(),
        total_tasks=db.count_tasks(),
        states_count={},
        estimate_hour=None,
        estimate_day=None
    )

    states = (
        TASK_PENDING,
        TASK_RUNNING,
        TASK_COMPLETED,
        TASK_RECOVERED,
        TASK_REPORTED,
        TASK_FAILED_ANALYSIS,
        TASK_FAILED_PROCESSING,
        TASK_FAILED_REPORTING
    )

    for state in states:
        report["states_count"][state] = db.count_tasks(state)

    offset = None

    # For the following stats we're only interested in completed tasks.
    tasks = db.count_tasks(status=TASK_COMPLETED)
    tasks += db.count_tasks(status=TASK_REPORTED)

    if tasks:
        # Get the time when the first task started and last one ended.
        started, completed = db.minmax_tasks()

        # It has happened that for unknown reasons completed and started were
        # equal in which case an exception is thrown, avoid this.
        if completed and started and int(completed - started):
            hourly = 60 * 60 * tasks / (completed - started)
        else:
            hourly = 0

        report["estimate_hour"] = int(hourly)
        report["estimate_day"] = int(24 * hourly)

    return render(request, "dashboard/index.html", {
        "report": report,
    })
