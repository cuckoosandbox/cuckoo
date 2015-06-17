#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import tarfile
import argparse
from datetime import datetime
from StringIO import StringIO
from zipfile import ZipFile, ZIP_STORED

try:
    from flask import Flask
    from flask import render_template as template
    from flask import request, make_response, jsonify, abort
except ImportError:
    sys.exit("ERROR: Flask library is missing (`pip install flask`)")

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file, delete_folder
from lib.cuckoo.core.database import Database, TASK_RUNNING, Task
from lib.cuckoo.core.startup import drop_privileges

# Global Database object.
db = Database()

# Initialize Flask app.
app = Flask(__name__)

@app.after_request
def custom_headers(response):
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

@app.route("/tasks/create/file", methods=["POST",])
@app.route("/v1/tasks/create/file", methods=["POST",])
def tasks_create_file():
    data = request.files.file
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    owner = request.forms.get("owner", "")
    memory = request.forms.get("memory", False)
    clock = request.forms.get("clock", None)

    if memory:
        memory = True
    enforce_timeout = request.forms.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True

    temp_file_path = store_temp_file(data.file.read(), data.filename)
    task_id = db.add_path(
        file_path=temp_file_path,
        package=package,
        timeout=timeout,
        priority=priority,
        options=options,
        machine=machine,
        platform=platform,
        tags=tags,
        custom=custom,
        owner=owner,
        memory=memory,
        enforce_timeout=enforce_timeout,
        clock=clock
    )

    return jsonify(task_id=task_id)

@app.route("/tasks/create/url", methods=["POST",])
@app.route("/v1/tasks/create/url", methods=["POST",])
def tasks_create_url():
    url = request.forms.get("url")
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    owner = request.forms.get("owner", "")

    memory = request.forms.get("memory", False)
    if memory:
        memory = True

    enforce_timeout = request.forms.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True

    clock = request.forms.get("clock", None)

    task_id = db.add_url(
        url=url,
        package=package,
        timeout=timeout,
        options=options,
        priority=priority,
        machine=machine,
        platform=platform,
        tags=tags,
        custom=custom,
        owner=owner,
        memory=memory,
        enforce_timeout=enforce_timeout,
        clock=clock
    )

    return jsonify(task_id)

@app.route("/tasks/list")
@app.route("/v1/tasks/list")
@app.route("/tasks/list/<int:limit>")
@app.route("/v1/tasks/list/<int:limit>")
@app.route("/tasks/list/<int:limit>/<int:offset>")
@app.route("/v1/tasks/list/<int:limit>/<int:offset>")
def tasks_list(limit=None, offset=None):
    response = {}

    response["tasks"] = []

    completed_after = request.GET.get("completed_after")
    if completed_after:
        completed_after = datetime.fromtimestamp(int(completed_after))

    owner = request.GET.get("owner")
    status = request.GET.get("status")

    for row in db.list_tasks(limit=limit, details=True, offset=offset,
                             completed_after=completed_after, owner=owner,
                             status=status, order_by=Task.completed_on.asc()):
        task = row.to_dict()
        task["guest"] = {}
        if row.guest:
            task["guest"] = row.guest.to_dict()

        task["errors"] = []
        for error in row.errors:
            task["errors"].append(error.message)

        task["sample"] = {}
        if row.sample_id:
            sample = db.view_sample(row.sample_id)
            task["sample"] = sample.to_dict()

        response["tasks"].append(task)

    return jsonify(response)

@app.route("/tasks/view/<int:task_id>")
@app.route("/v1/tasks/view/<int:task_id>")
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

        entry["sample"] = {}
        if task.sample_id:
            sample = db.view_sample(task.sample_id)
            entry["sample"] = sample.to_dict()

        response["task"] = entry
    else:
        return HTTPError(404, "Task not found")

    return jsonify(response)

@app.route("/tasks/reschedule/<int:task_id>")
@app.route("/v1/tasks/reschedule/<int:task_id>")
def tasks_reschedule(task_id):
    response = {}

    if not db.view_task(task_id):
        return HTTPError(404, "There is no analysis with the specified ID")

    if db.reschedule(task_id):
        response["status"] = "OK"
    else:
        return HTTPError(500, "An error occurred while trying to "
                              "reschedule the task")

    return jsonify(response)

@app.route("/tasks/delete/<int:task_id>")
@app.route("/v1/tasks/delete/<int:task_id>")
def tasks_delete(task_id):
    response = {}

    task = db.view_task(task_id)
    if task:
        if task.status == TASK_RUNNING:
            return HTTPError(500, "The task is currently being "
                                  "processed, cannot delete")

        if db.delete_task(task_id):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage",
                                       "analyses", "%d" % task_id))
            response["status"] = "OK"
        else:
            return HTTPError(500, "An error occurred while trying to "
                                  "delete the task")
    else:
        return HTTPError(404, "Task not found")

    return jsonify(response)

@app.route("/tasks/report/<int:task_id>")
@app.route("/v1/tasks/report/<int:task_id>")
@app.route("/tasks/report/<int:task_id>/<report_format>")
@app.route("/v1/tasks/report/<int:task_id>/<report_format>")
def tasks_report(task_id, report_format="json"):
    formats = {
        "json": "report.json",
        "html": "report.html",
        "maec": "report.maec-1.1.xml",
        "metadata": "report.metadata.xml",
    }

    bz_formats = {
        "all": {"type": "-", "files": ["memory.dmp"]},
        "dropped": {"type": "+", "files": ["files"]},
    }

    tar_formats = {
        "bz2": "w:bz2",
        "gz": "w:gz",
        "tar": "w",
    }

    if report_format.lower() in formats:
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                   "%d" % task_id, "reports",
                                   formats[report_format.lower()])
    elif report_format.lower() in bz_formats:
            bzf = bz_formats[report_format.lower()]
            srcdir = os.path.join(CUCKOO_ROOT, "storage",
                                  "analyses", "%d" % task_id)
            s = StringIO()

            # By default go for bz2 encoded tar files (for legacy reasons.)
            tarmode = tar_formats.get(request.GET.get("tar"), "w:bz2")

            tar = tarfile.open(fileobj=s, mode=tarmode)
            for filedir in os.listdir(srcdir):
                if bzf["type"] == "-" and filedir not in bzf["files"]:
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

@app.route("/tasks/screenshots/<int:task_id>")
@app.route("/v1/tasks/screenshots/<int:task_id>")
@app.route("/tasks/screenshots/<int:task_id>/<screenshot>")
@app.route("/v1/tasks/screenshots/<int:task_id>/<screenshot>")
def task_screenshots(task_id=0, screenshot=None):
    folder_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "shots")

    if os.path.exists(folder_path):
        if screenshot:
            screenshot_name = "{0}.jpg".format(screenshot)
            screenshot_path = os.path.join(folder_path, screenshot_name)
            if os.path.exists(screenshot_path):
                # TODO: Add content disposition.
                response.content_type = "image/jpeg"
                return open(screenshot_path, "rb").read()
            else:
                return HTTPError(404, screenshot_path)
        else:
            zip_data = StringIO()
            with ZipFile(zip_data, "w", ZIP_STORED) as zip_file:
                for shot_name in os.listdir(folder_path):
                    zip_file.write(os.path.join(folder_path, shot_name), shot_name)

            # TODO: Add content disposition.
            response.content_type = "application/zip"
            return zip_data.getvalue()
    else:
        return HTTPError(404, folder_path)

@app.route("/files/view/md5/<md5>")
@app.route("/v1/files/view/md5/<md5>")
@app.route("/files/view/sha256/<sha256>")
@app.route("/v1/files/view/sha256/<sha256>")
@app.route("/files/view/id/<int:sample_id>")
@app.route("/v1/files/view/id/<int:sample_id>")
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

    return jsonify(response)

@app.route("/files/get/<sha256>")
@app.route("/v1/files/get/<sha256>")
def files_get(sha256):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)
    if os.path.exists(file_path):
        response.content_type = "application/octet-stream; charset=UTF-8"
        return open(file_path, "rb").read()
    else:
        return HTTPError(404, "File not found")

@app.route("/pcap/get/<int:task_id>")
@app.route("/v1/pcap/get/<int:task_id>")
def pcap_get(task_id):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                             "%d" % task_id, "dump.pcap")
    if os.path.exists(file_path):
        response.content_type = "application/octet-stream; charset=UTF-8"
        try:
            return open(file_path, "rb").read()
        except:
            return HTTPError(500, "An error occurred while reading PCAP")
    else:
        return HTTPError(404, "File not found")

@app.route("/machines/list")
@app.route("/v1/machines/list")
def machines_list():
    response = {}

    machines = db.list_machines()

    response["machines"] = []
    for row in machines:
        response["machines"].append(row.to_dict())

    return jsonify(response)

@app.route("/machines/view/<name>")
@app.route("/v1/machines/view/<name>")
def machines_view(name=None):
    response = {}

    machine = db.view_machine(name=name)
    if machine:
        response["machine"] = machine.to_dict()
    else:
        return HTTPError(404, "Machine not found")

    return jsonify(response)

@app.route("/cuckoo/status")
@app.route("/v1/cuckoo/status")
def cuckoo_status():
    # In order to keep track of the diskspace statistics of the temporary
    # directory we create a temporary file so we can statvfs() on that.
    temp_file = store_temp_file("", "status")

    paths = dict(
        binaries=os.path.join(CUCKOO_ROOT, "storage", "binaries"),
        analyses=os.path.join(CUCKOO_ROOT, "storage", "analyses"),
        temporary=temp_file,
    )

    diskspace = {}
    for key, path in paths.items():
        if hasattr(os, "statvfs"):
            stats = os.statvfs(path)
            diskspace[key] = dict(
                free=stats.f_bavail * stats.f_frsize,
                total=stats.f_blocks * stats.f_frsize,
                used=(stats.f_blocks - stats.f_bavail) * stats.f_frsize,
            )

    # Now we remove the temporary file and its parent directory.
    os.unlink(temp_file)
    os.rmdir(os.path.dirname(temp_file))

    # Get the CPU load.
    if hasattr(os, "getloadavg"):
        cpuload = os.getloadavg()
    else:
        cpuload = []

    response = dict(
        version=CUCKOO_VERSION,
        hostname=socket.gethostname(),
        machines=dict(
            total=len(db.list_machines()),
            available=db.count_machines_available()
        ),
        tasks=dict(
            total=db.count_tasks(),
            pending=db.count_tasks("pending"),
            running=db.count_tasks("running"),
            completed=db.count_tasks("completed"),
            reported=db.count_tasks("reported")
        ),
        diskspace=diskspace,
        cpuload=cpuload,
    )

    return jsonify(response)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the API server on",
        default="localhost", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the API server on",
        default=8090, action="store", required=False)
    parser.add_argument("-u", "--user", type=str,
        help="Drop user privileges to this user")
    args = parser.parse_args()

    if args.user:
        drop_privileges(args.user)

    app.run(host=args.host, port=int(args.port))
