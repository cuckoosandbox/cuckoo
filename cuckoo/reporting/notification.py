# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import calendar
import datetime
import json
import requests

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class Notification(Report):
    """Notifies external service about finished analysis via URL."""
    order = 3

    def run(self, results):
        post = {
            "task_id": self.task["id"],
            "identifier": self.options.get("identifier"),
            "data": json.dumps(
                results.get("info"), default=default, sort_keys=False
            )
        }

        try:
            requests.post(self.options.get("url"), data=post)
        except Exception as e:
            raise CuckooReportError(
                "Failed posting message via Notification: %s" % e
            )
