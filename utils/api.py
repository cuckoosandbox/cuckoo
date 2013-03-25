#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import json
import argparse
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_STORED

try:
    from bottle import Bottle, route, run, request, server_names, ServerAdapter, hook, response, HTTPError, static_file
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
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", False)
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
                          custom=custom,
                          memory=memory,
                          enforce_timeout=enforce_timeout)

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
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", False)
    if memory:
        memory = True
    enforce_timeout = request.forms.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True

    task_id = db.add_url(url=url,
                         package=package,
                         timeout=timeout,
                         options=options,
                         priority=priority,
                         machine=machine,
                         platform=platform,
                         custom=custom,
                         memory=memory,
                         enforce_timeout=enforce_timeout)

    response["task_id"] = task_id
    return jsonize(response)

@route("/tasks/list", method="GET")
@route("/tasks/list/<limit>", method="GET")
def tasks_list(limit=None):
    response = {}

    response["tasks"] = []
    for row in db.list_tasks(limit).all():
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

    task = db.view_task(task_id)
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
    response = {}

    formats = {
        "json" : "report.json",
        "html" : "report.html",
        "maec" : "report.maec-1.1.xml",
        "metadata" : "report.metadata.xml",
        "pickle" : "report.pickle"
    }

    if report_format.lower() in formats:
        report_path = os.path.join(CUCKOO_ROOT,
                                   "storage",
                                   "analyses",
                                   task_id,
                                   "reports",
                                   formats[report_format.lower()])
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
        sample = db.find_sample(md5=md5)[0]
    elif sha256:
        sample = db.find_sample(sha256=sha256)[0]
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

@route("/dropped/get/<task_id>/all")
def dropped_get_all(task_id):
    root = os.path.abspath(os.path.join(CUCKOO_ROOT, "storage", "analyses",
                           task_id, "files"))

    # Check to ensure the task actually exists
    if not os.path.exists(root):
        return HTTPError(404, "No task with id %s" % task_id)

    download = "dropped_%s.zip" % task_id
    zip_data = StringIO()

    with ZipFile(zip_data, "w", ZIP_STORED) as dropped:
        for base, dirs, files in os.walk(root):
            for name in files:
                # Save files to the zip without their full paths
                path = os.path.join(base, name)
                archive_name = os.path.join(os.path.split(base)[1], name)

                try:
                    dropped.write(path, archive_name)
                except IOError:
                    return HTTPError(404, "Error accessing dropped files.")

    response.content_type = "application/octet-stream; charset=UTF-8"
    response.set_header("Content-Disposition", 'attachment; filename="%s"'
                        % download)
    data = zip_data.getvalue()
    zip_data.close()
    return data

@route("/dropped/get/<task_id>/<path:path>")
def dropped_get(task_id, path):
    root = os.path.abspath(os.path.join(CUCKOO_ROOT, "storage", "analyses",
                           task_id, "files"))

    # Check to ensure the task actually exists
    if not os.path.exists(root):
        return HTTPError(404, "No task with id %s" % task_id)

    (base, filename) = os.path.split(path)
    random_dir = os.path.split(base)[1]

    serving_root = os.path.abspath(os.path.join(root, random_dir))
    return static_file(filename, serving_root, download=filename)

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
