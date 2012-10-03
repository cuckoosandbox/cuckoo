#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json

from bottle import Bottle, run, request, server_names, ServerAdapter

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.utils import store_temp_file, File
from lib.cuckoo.core.database import Database

def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

def report_error(error_code):
    return jsonize({"error" : True, "error_code" : error_code, "error_message" : ERRORS[error_code]})

app = Bottle()

@app.get("/task/list")
def task_list():
    response = {"error" : False}

    db = Database()

    response["tasks"] = []
    for row in db.list().all():
        response["tasks"].append(row.to_dict())

    return jsonize(response)

@app.post("/task/create", method="POST")
def task_create():
    response = {"error" : False}

    data = request.files.file
    package = request.forms.get("package")
    timeout = request.forms.get("timeout")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options")
    machine = request.forms.get("machine")
    platform = request.forms.get("platform")
    custom = request.forms.get("custom")

    temp_file_path = store_temp_file(data.file.read(), data.filename)
    db = Database()
    task_id = db.add(file_path=temp_file_path, md5=File(temp_file_path).get_md5(), package=package, timeout=timeout, priority=priority, options=options, machine=machine, platform=platform, custom=custom)

    response["task_id"] = task_id
    return jsonize(response)

if __name__ == "__main__":
    run(app, host="0.0.0.0", port=8888)