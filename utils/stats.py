#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import sys
import time

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING

def timestamp(dt):
    """Returns the timestamp of a datetime object."""
    return time.mktime(dt.timetuple())

def main():
    db = Database()

    print("%d samples in db" % db.count_samples())
    print("%d tasks in db" % db.count_tasks())

    states = (
        TASK_PENDING, TASK_RUNNING,
        TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED,
        TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING
    )

    for state in states:
        print("%s %d tasks" % (state, db.count_tasks(state)))

    # Later on we might be interested in only calculating stats for all
    # tasks starting at a certain offset, because the Cuckoo daemon may
    # have been restarted at some point in time.
    offset = None

    # For the following stats we're only interested in completed tasks.
    tasks = db.list_tasks(offset=offset, status=TASK_COMPLETED)
    tasks += db.list_tasks(offset=offset, status=TASK_REPORTED)

    if tasks:
        # Get the time when the first task started.
        started = min(timestamp(task.started_on) for task in tasks)

        # Get the time when the last task completed.
        stamps = []
        for task in tasks:
            try:
                stamps.append(timestamp(task.completed_on))
            except AttributeError:
                pass

        completed = max(stamps)

        # Get the amount of tasks that actually completed.
        finished = len(tasks)

        hourly = 60 * 60 * finished / (completed - started)

        print("roughly %d tasks an hour" % int(hourly))
        print("roughly %d tasks a day" % int(24 * hourly))

if __name__ == "__main__":
    main()
