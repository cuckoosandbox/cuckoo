# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import calendar
import json
from datetime import datetime

from django.shortcuts import render

def json_default(obj):
    if hasattr(obj, "to_dict"):
        return obj.to_dict()

    if isinstance(obj, datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class json_default_response(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()

        if isinstance(obj, datetime):
            if obj.utcoffset() is not None:
                obj = obj - obj.utcoffset()
            return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
        raise TypeError("%r is not JSON serializable" % obj)

def view_error(request, msg):
    return render(request, "error.html", {
        "error": msg
    })

def get_directory_size(path):
    """recursive"""

    size = 0
    for path_dir, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(path_dir, f)
            size += os.path.getsize(fp)

    return size
