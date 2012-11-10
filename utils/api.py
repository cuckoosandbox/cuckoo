#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import argparse

from bottle import Bottle, route, run, request, server_names, ServerAdapter

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database

errors = {
    "task_not_found" : "The specified task does not exist",
    "file_not_found" : "The specified file does not exist",
    "machine_not_found" : "The specified machine does not exist"
}

def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

def report_error(error_code):
    return jsonize({"error" : True, "error_code" : error_code, "error_message" : errors[error_code]})

@route("/tasks/create/file", method="POST")
def tasks_create_file():
    response = {"error" : False}

    data = request.files.file
    package = request.forms.get("package")
    timeout = request.forms.get("timeout")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options")
    machine = request.forms.get("machine")
    platform = request.forms.get("platform")
    custom = request.forms.get("custom")
    memory = request.forms.get("memory", False)
    if memory:
        memory = True

    temp_file_path = store_temp_file(data.file.read(), data.filename)
    db = Database()
    task_id = db.add_path(file_path=temp_file_path,
                          package=package,
                          timeout=timeout,
                          priority=priority,
                          options=options,
                          machine=machine,
                          platform=platform,
                          custom=custom,
                          memory=memory)

    response["task_id"] = task_id
    return jsonize(response)

@route("/tasks/create/url", method="POST")
def tasks_create_url():
    response = {"error" : False}

    url = request.forms.get("url")
    package = request.forms.get("package")
    timeout = request.forms.get("timeout")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options")
    machine = request.forms.get("machine")
    platform = request.forms.get("platform")
    custom = request.forms.get("custom")
    memory = request.forms.get("memory", False)
    if memory:
        memory = True

    db = Database()
    task_id = db.add_url(url=url,
                         package=package,
                         timeout=timeout,
                         options=options,
                         priority=priority,
                         machine=machine,
                         platform=platform,
                         custom=custom,
                         memory=memory)

    response["task_id"] = task_id
    return jsonize(response)

@route("/tasks/list", method="GET")
@route("/tasks/list/<limit>", method="GET")
def tasks_list(limit=None):
    response = {"error" : False}

    db = Database()

    response["tasks"] = []
    for row in db.list_tasks(limit).all():
        task = row.to_dict()
        guest = row.guest
        task["guest"] = {}
        if guest:
            task["guest"] = guest.to_dict()
        response["tasks"].append(task)

    return jsonize(response)

@route("/tasks/view/<task_id>", method="GET")
def tasks_view(task_id):
    response = {"error" : False}

    db = Database()

    task = db.view_task(task_id)
    if task:
        entry = task.to_dict()
        guest = task.guest
        entry["guest"] = {}
        if guest:
            entry["guest"] = guest.to_dict()
        response["task"] = entry
    else:
        return report_error("task_not_found")

    return jsonize(response)

@route("/files/view/md5/<md5>", method="GET")
@route("/files/view/id/<sample_id>", method="GET")
def files_view(md5=None, sample_id=None):
    response = {"error" : False}

    db = Database()
    if md5:
        sample = db.find_sample_by_md5(md5)[0]
    elif sample_id:
        sample = db.view_sample(sample_id)

    if sample:
        response["sample"] = sample.to_dict()
    else:
        return report_error("file_not_found")

    return jsonize(response)

@route("/files/get/<md5>", method="GET")
def files_get(md5):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", md5)
    if os.path.exists(file_path):
        return open(file_path, "rb").read()
    else:
        return report_error("file_not_found")

@route("/machines/list", method="GET")
def machines_list():
    response = {"error" : False}

    db = Database()
    machines = db.list_machines()

    response["machines"] = []
    for row in machines:
        response["machines"].append(row.to_dict())

    return jsonize(response)

@route("/machines/view/<name>", method="GET")
def machines_view(name=None):
    response = {"error" : False}

    db = Database()

    machine = db.view_machine(name=name)
    if machine:
        response["machine"] = machine.to_dict()
    else:
        return report_error("machine_not_found")

    return jsonize(response)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the API server on", default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the API server on", default=8090, action="store", required=False)
    args = parser.parse_args()

    run(host=args.host, port=args.port)
