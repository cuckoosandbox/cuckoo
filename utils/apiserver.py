#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json

from cherrypy import _cpwsgiserver3
from bottle import Bottle, run, request, server_names, ServerAdapter

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database

def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

def report_error(error_code):
    return jsonize({"error" : True, "error_code" : error_code, "error_message" : ERRORS[error_code]})

app = Bottle()

@app.post("/task/create", method="POST")
def task_create():
    response = {"error" : False}

    package = request.forms.get("package")
    timeout = request.forms.get("timeout")
    priority = request.forms.get("priority")
    options = request.forms.get("options")
    machine = request.forms.get("machine")
    platform = request.forms.get("platform")
    custom = request.forms.get("custom")

    db = Database()
    db.add(file_path="/tmp/a", package=package, timeout=timeout, priority=priority, options=options, machine=machine, platform=platform, custom=custom)

if __name__ == "__main__":
    run(app, host="localhost", port="8080")