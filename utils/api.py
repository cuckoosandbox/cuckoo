#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import argparse
import tarfile
import StringIO

try:
    from bottle import Bottle, route, run, request, server_names, ServerAdapter, hook, response, HTTPError
except ImportError:
    sys.exit("ERROR: Bottle.py library is missing")

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file, delete_folder
from lib.cuckoo.core.database import Database

# Global DB pointer.
db = Database()

def jsonize(data):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data
    """ 
    response.content_type = "application/json; charset=UTF-8"
    return json.dumps(data, sort_keys=False, indent=4)

@hook("after_request")
def custom_headers():
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"

@route("/tasks/create/file", method="POST")
def tasks_create_file():
    response = {}

    data = request.files.file
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", False)
    clock = request.forms.get("clock", None)
    if memory:
        memory = True
    enforce_timeout = request.forms.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True

    temp_file_path = store_temp_file(data.file.read(), data.filename)
    task_id = db.add_path(file_path=temp_file_path,
                          package=package,
                          timeout=timeout,
                          priority=priority,
                          options=options,
                          machine=machine,
                          platform=platform,
                          tags=tags,
                          custom=custom,
                          memory=memory,
                          enforce_timeout=enforce_timeout,
                          clock=clock)

    response["task_id"] = task_id
    return jsonize(response)

@route("/tasks/create/url", method="POST")
def tasks_create_url():
    response = {}

    url = request.forms.get("url")
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", False)
    if memory:
        memory = True
    enforce_timeout = request.forms.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True
    clock = request.forms.get("clock", None)

    task_id = db.add_url(url=url,
                         package=package,
                         timeout=timeout,
                         options=options,
                         priority=priority,
                         machine=machine,
                         platform=platform,
                         tags=tags,
                         custom=custom,
                         memory=memory,
                         enforce_timeout=enforce_timeout,
                         clock=clock)

    response["task_id"] = task_id
    return jsonize(response)

@route("/tasks/list", method="GET")
@route("/tasks/list/<limit:int>", method="GET")
@route("/tasks/list/<limit:int>/<offset:int>", method="GET")
def tasks_list(limit=None, offset=None):
    response = {}

    response["tasks"] = []

    for row in db.list_tasks(limit=limit, details=True, offset=offset):
        task = row.to_dict()
        task["guest"] = {}
        if row.guest:
            task["guest"] = row.guest.to_dict()

        task["errors"] = []
        for error in row.errors:
            task["errors"].append(error.message)

        response["tasks"].append(task)

    return jsonize(response)

@route("/tasks/view/<task_id>", method="GET")
def tasks_view(task_id):
    response = {}

    task = db.view_task(task_id, details=True)
    if task:
        entry = task.to_dict()
        entry["guest"] = {}
        if task.guest:
            entry["guest"] = task.guest.to_dict()

        entry["errors"] = []
        for error in task.errors:
            entry["errors"].append(error.message)

        response["task"] = entry
    else:
        return HTTPError(404, "Task not found")

    return jsonize(response)

@route("/tasks/reschedule/<task_id>", method="GET")
def tasks_reschedule(task_id):
    response = {}

    if not db.view_task(task_id):
        return HTTPError(404, "There is no analysis with the specified ID")

    if db.reschedule(task_id):
        response["status"] = "OK"
    else:
        return HTTPError(500, "An error occurred while trying to reschedule the task")

    return jsonize(response)

@route("/tasks/delete/<task_id>", method="GET")
def tasks_delete(task_id):
    response = {}

    task = db.view_task(task_id)
    if task:
        if task.status == "processing":
            return HTTPError(500, "The task is currently being processed, cannot delete")

        if db.delete_task(task_id):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id))
            response["status"] = "OK"
        else:
            return HTTPError(500, "An error occurred while trying to delete the task")
    else:
        return HTTPError(404, "Task not found")

    return jsonize(response)

@route("/tasks/report/<task_id>", method="GET")
@route("/tasks/report/<task_id>/<report_format>", method="GET")
def tasks_report(task_id, report_format="json"):
    formats = {
        "json" : "report.json",
        "html" : "report.html",
        "maec" : "report.maec-1.1.xml",
        "metadata" : "report.metadata.xml"
    }

    bz_formats = {
        "all": {"type": "-", "files": ["memory.dmp"]},
        "dropped": {"type": "+", "files": ["files"]},
    }

    if report_format.lower() in formats:
        report_path = os.path.join(CUCKOO_ROOT,
                                   "storage",
                                   "analyses",
                                   task_id,
                                   "reports",
                                   formats[report_format.lower()])
    elif report_format.lower() in bz_formats:
            bzf = bz_formats[report_format.lower()]
            srcdir = os.path.join(CUCKOO_ROOT,
                                   "storage",
                                   "analyses",
                                   task_id)
            s = StringIO.StringIO()
            tar = tarfile.open(fileobj=s, mode="w:bz2")
            for filedir in os.listdir(srcdir):
                if bzf["type"] == "-" and not filedir in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
                if bzf["type"] == "+" and filedir in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
            tar.close()
            response.content_type = "application/x-tar; charset=UTF-8"
            return s.getvalue()
    else:
        return HTTPError(400, "Invalid report format")

    if os.path.exists(report_path):
        return open(report_path, "rb").read()
    else:
        return HTTPError(404, "Report not found")

@route("/files/view/md5/<md5>", method="GET")
@route("/files/view/sha256/<sha256>", method="GET")
@route("/files/view/id/<sample_id>", method="GET")
def files_view(md5=None, sha256=None, sample_id=None):
    response = {}

    if md5:
        sample = db.find_sample(md5=md5)
    elif sha256:
        sample = db.find_sample(sha256=sha256)
    elif sample_id:
        sample = db.view_sample(sample_id)
    else:
        return HTTPError(400, "Invalid lookup term")

    if sample:
        response["sample"] = sample.to_dict()
    else:
        return HTTPError(404, "File not found")

    return jsonize(response)

@route("/files/get/<sha256>", method="GET")
def files_get(sha256):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)
    if os.path.exists(file_path):
        response.content_type = "application/octet-stream; charset=UTF-8"
        return open(file_path, "rb").read()
    else:
        return HTTPError(404, "File not found")

@route("/machines/list", method="GET")
def machines_list():
    response = {}

    machines = db.list_machines()

    response["machines"] = []
    for row in machines:
        response["machines"].append(row.to_dict())

    return jsonize(response)

@route("/machines/view/<name>", method="GET")
def machines_view(name=None):
    response = {}

    machine = db.view_machine(name=name)
    if machine:
        response["machine"] = machine.to_dict()
    else:
        return HTTPError(404, "Machine not found")

    return jsonize(response)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the API server on", default="localhost", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the API server on", default=8090, action="store", required=False)
    args = parser.parse_args()

    run(host=args.host, port=args.port)
