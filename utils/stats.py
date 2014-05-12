#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import os.path
import sys
import time
import datetime
import operator

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING

def timestamp(dt):
    """Returns the timestamp of a datetime object."""
    return time.mktime(dt.timetuple())

def main(profile=False):
    """
    @param profile: Show profiling information
    """
    db = Database()

    print("%d samples in db" % db.count_samples())
    print("%d tasks in db" % db.count_tasks())

    states = (
        TASK_PENDING, TASK_RUNNING,
        TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED,
        TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING,
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

    if profile:
        started = {}
        total = {}
        print ("Profiling:")
        with open(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log")) as fh:
            for line in fh.readlines():
                if " DEBUG: profiling:" in line:
                    edate, etime, mod, dbg, message = line.split(" ", 4)
                    prof, pos, section, module, tid = message.split(":")
                    if pos == "start":
                        started[section+":"+module+":"+tid] = edate + " " + etime
                    elif pos == "stop":
                        starttime = started[section+":"+module+":"+tid]
                        endtime = edate + " " + etime
                        start = datetime.datetime.strptime(starttime, "%Y-%m-%d %H:%M:%S,%f")
                        end = datetime.datetime.strptime(endtime, "%Y-%m-%d %H:%M:%S,%f")
                        diff = end-start
                        name = section + ":" + module
                        if not name in total:
                            total[name] = 0.0
                        total[name] += diff.total_seconds()
        sorted_total = sorted(total.iteritems(), key=operator.itemgetter(1))
        for name, val in sorted_total:
            print "%s: %0.4f" % (name, val)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", help="Profile usign debug logs", action="store_true", required=False)
    args = parser.parse_args()
    main(profile=args.profile)
