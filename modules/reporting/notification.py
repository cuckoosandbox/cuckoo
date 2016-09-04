# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import datetime
import calendar

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooOperationalError

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class Notification(Report):
    """Notifies external service about finished analysis via URL."""

    def run(self, results):
        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The Notification reporting module requires the requests "
                "library (install with `pip install requests`)"
            )

        post = {
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
