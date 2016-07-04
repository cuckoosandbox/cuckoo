#!/usr/bin/env python
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
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
    from flask import Flask, request, jsonify, make_response
except ImportError:
    sys.exit("ERROR: Flask library is missing (`pip install flask`)")

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file, delete_folder
from lib.cuckoo.core.database import Database, TASK_RUNNING, Task
from lib.cuckoo.core.database import TASK_REPORTED, TASK_COMPLETED
from lib.cuckoo.core.startup import drop_privileges
from lib.cuckoo.core.rooter import rooter

# Global Database object.
db = Database()

# Initialize Flask app.
app = Flask(__name__)

def json_error(status_code, message):
    """Return a JSON object with a HTTP error code."""
    r = jsonify(message=message)
    r.status_code = status_code
    return r

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

@app.route("/tasks/create/file", methods=["POST"])
@app.route("/v1/tasks/create/file", methods=["POST"])
def tasks_create_file():
    data = request.files["file"]
    package = request.form.get("package", "")
    timeout = request.form.get("timeout", "")
    priority = request.form.get("priority", 1)
    options = request.form.get("options", "")
    machine = request.form.get("machine", "")
    platform = request.form.get("platform", "")
    tags = request.form.get("tags", None)
    custom = request.form.get("custom", "")
    owner = request.form.get("owner", "")
    memory = request.form.get("memory", False)
    clock = request.form.get("clock", None)

    if memory:
        memory = True
    enforce_timeout = request.form.get("enforce_timeout", False)

    if enforce_timeout:
        enforce_timeout = True

    temp_file_path = store_temp_file(data.read(), data.filename)

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

@app.route("/tasks/create/url", methods=["POST"])
@app.route("/v1/tasks/create/url", methods=["POST"])
def tasks_create_url():
    url = request.form.get("url")
    package = request.form.get("package", "")
    timeout = request.form.get("timeout", "")
    priority = request.form.get("priority", 1)
    options = request.form.get("options", "")
    machine = request.form.get("machine", "")
    platform = request.form.get("platform", "")
    tags = request.form.get("tags", None)
    custom = request.form.get("custom", "")
    owner = request.form.get("owner", "")

    memory = request.form.get("memory", False)
    if memory:
        memory = True

    enforce_timeout = request.form.get("enforce_timeout", False)
    if enforce_timeout:
        enforce_timeout = True

    clock = request.form.get("clock", None)

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

    return jsonify(task_id=task_id)

@app.route("/tasks/list")
@app.route("/v1/tasks/list")
@app.route("/tasks/list/<int:limit>")
@app.route("/v1/tasks/list/<int:limit>")
@app.route("/tasks/list/<int:limit>/<int:offset>")
@app.route("/v1/tasks/list/<int:limit>/<int:offset>")
def tasks_list(limit=None, offset=None):
    response = {}

    response["tasks"] = []

    completed_after = request.args.get("completed_after")
    if completed_after:
        completed_after = datetime.fromtimestamp(int(completed_after))

    owner = request.args.get("owner")
    status = request.args.get("status")

    for row in db.list_tasks(limit=limit, details=True, offset=offset,
                             completed_after=completed_after, owner=owner,
                             status=status, order_by=Task.completed_on.asc()):
        task = row.to_dict()

        # Sanitize the target in case it contains non-ASCII characters as we
        # can't pass along an encoding to flask's jsonify().
        task["target"] = task["target"].decode("latin-1")

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
        r = jsonify(message="Task not found")
        r.status_code = 404
        return r

    return jsonify(response)

@app.route("/tasks/reschedule/<int:task_id>")
@app.route("/tasks/reschedule/<int:task_id>/<int:priority>")
@app.route("/v1/tasks/reschedule/<int:task_id>")
@app.route("/v1/tasks/reschedule/<int:task_id>/<int:priority>")
def tasks_reschedule(task_id, priority=None):
    response = {}

    if not db.view_task(task_id):
        return json_error(404, "There is no analysis with the specified ID")

    new_task_id = db.reschedule(task_id, priority)
    if new_task_id:
        response["status"] = "OK"
        response["task_id"] = new_task_id
    else:
        return json_error(500, "An error occurred while trying to "
                          "reschedule the task")

    return jsonify(response)

@app.route("/tasks/delete/<int:task_id>")
@app.route("/v1/tasks/delete/<int:task_id>")
def tasks_delete(task_id):
    response = {}

    task = db.view_task(task_id)
    if task:
        if task.status == TASK_RUNNING:
            return json_error(500, "The task is currently being "
                              "processed, cannot delete")

        if db.delete_task(task_id):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage",
                                       "analyses", "%d" % task_id))
            response["status"] = "OK"
        else:
            return json_error(500, "An error occurred while trying to "
                              "delete the task")
    else:
        return json_error(404, "Task not found")

    return jsonify(response)

@app.route("/tasks/report/<int:task_id>")
@app.route("/v1/tasks/report/<int:task_id>")
@app.route("/tasks/report/<int:task_id>/<report_format>")
@app.route("/v1/tasks/report/<int:task_id>/<report_format>")
def tasks_report(task_id, report_format="json"):
    formats = {
        "json": "report.json",
        "html": "report.html",
    }

    bz_formats = {
        "all": {"type": "-", "files": ["memory.dmp"]},
        "dropped": {"type": "+", "files": ["files"]},
        "package_files": {"type": "+", "files": ["package_files"]},
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

        # By default go for bz2 encoded tar files (for legacy reasons).
        tarmode = tar_formats.get(request.args.get("tar"), "w:bz2")

        tar = tarfile.open(fileobj=s, mode=tarmode, dereference=True)
        for filedir in os.listdir(srcdir):
            filepath = os.path.join(srcdir, filedir)
            if not os.path.exists(filepath):
                continue
            if bzf["type"] == "-" and filedir not in bzf["files"]:
                tar.add(filepath, arcname=filedir)
            if bzf["type"] == "+" and filedir in bzf["files"]:
                tar.add(filepath, arcname=filedir)
        tar.close()

        response = make_response(s.getvalue())
        response.headers["Content-Type"] = \
            "application/x-tar; charset=UTF-8"
        return response
    else:
        return json_error(400, "Invalid report format")

    if os.path.exists(report_path):
        if report_format == "json":
            response = make_response(open(report_path, "rb").read())
            response.headers["Content-Type"] = "application/json"
            return response
        else:
            return open(report_path, "rb").read()
    else:
        return json_error(404, "Report not found")

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
                response = make_response(open(screenshot_path, "rb").read())
                response.headers["Content-Type"] = "image/jpeg"
                return response
            else:
                return json_error(404, "Screenshot not found!")
        else:
            zip_data = StringIO()
            with ZipFile(zip_data, "w", ZIP_STORED) as zip_file:
                for shot_name in os.listdir(folder_path):
                    zip_file.write(os.path.join(folder_path, shot_name), shot_name)

            # TODO: Add content disposition.
            response = make_response(zip_data.getvalue())
            response.headers["Content-Type"] = "application/zip"
            return response
        return json_error(404, "Task not found")

@app.route("/tasks/rereport/<int:task_id>")
def rereport(task_id):
    task = db.view_task(task_id)
    if task:
        if task.status == TASK_REPORTED:
            db.set_status(task_id, TASK_COMPLETED)
            return jsonify(success=True)

        return jsonify(success=False)
    else:
        return json_error(404, "Task not found")

@app.route("/tasks/reboot/<int:task_id>")
def reboot(task_id):
    reboot_id = Database().add_reboot(task_id=task_id)
    if not reboot_id:
        return json_error(404, "Error creating reboot task")

    return jsonify(task_id=task_id, reboot_id=reboot_id)

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
        return json_error(400, "Invalid lookup term")

    if sample:
        response["sample"] = sample.to_dict()
    else:
        return json_error(404, "File not found")

    return jsonify(response)

@app.route("/files/get/<sha256>")
@app.route("/v1/files/get/<sha256>")
def files_get(sha256):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)
    if os.path.exists(file_path):
        response = make_response(open(file_path, "rb").read())
        response.headers["Content-Type"] = \
            "application/octet-stream; charset=UTF-8"
        return response
    else:
        return json_error(404, "File not found")

@app.route("/pcap/get/<int:task_id>")
@app.route("/v1/pcap/get/<int:task_id>")
def pcap_get(task_id):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                             "%d" % task_id, "dump.pcap")
    if os.path.exists(file_path):
        try:
            # TODO This could be a big file, so eventually we have to switch
            # to app.send_static_file() instead.
            response = make_response(open(file_path, "rb").read())
            response.headers["Content-Type"] = \
                "application/octet-stream; charset=UTF-8"
            return response
        except:
            return json_error(500, "An error occurred while reading PCAP")
    else:
        return json_error(404, "File not found")

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
        return json_error(404, "Machine not found")

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
        if hasattr(os, "statvfs") and os.path.isdir(path):
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

    if os.path.isfile("/proc/meminfo"):
        values = {}
        for line in open("/proc/meminfo"):
            key, value = line.split(":", 1)
            values[key.strip()] = value.replace("kB", "").strip()

        if "MemAvailable" in values and "MemTotal" in values:
            memory = 100.0 * int(values["MemFree"]) / int(values["MemTotal"])
        else:
            memory = None
    else:
        memory = None

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
        memory=memory,
    )

    return jsonify(response)

@app.route("/memory/list/<int:task_id>")
def memorydumps_list(task_id):
    folder_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory")

    if os.path.exists(folder_path):
        memory_files = []
        memory_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory")
        for subdir, dirs, files in os.walk(memory_path):
            for filename in files:
                memory_files.append(filename.replace(".dmp", ""))

        if len(memory_files) == 0:
            return json_error(404, "Memory dump not found")

        return jsonify({"dump_files": memory_files})
    else:
        return json_error(404, "Memory dump not found")

@app.route("/memory/get/<int:task_id>/<pid>")
def memorydumps_get(task_id, pid=None):
    folder_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory")

    if os.path.exists(folder_path):
        if pid:
            pid_name = "{0}.dmp".format(pid)
            pid_path = os.path.join(folder_path, pid_name)
            if os.path.exists(pid_path):
                response = make_response(open(pid_path, "rb").read())
                response.headers["Content-Type"] = \
                    "application/octet-stream; charset=UTF-8"
                return response
            else:
                return json_error(404, "Memory dump not found")
        else:
            return json_error(404, "Memory dump not found")
    else:
        return json_error(404, "Memory dump not found")

@app.route("/vpn/status")
def vpn_status():
    status = rooter("vpn_status")
    if status is None:
        return json_error(500, "Rooter not available")

    return jsonify({"vpns": status})

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
