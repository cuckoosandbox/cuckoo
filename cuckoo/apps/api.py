# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import hashlib
import io
import logging
import multiprocessing
import os
import socket
import tarfile
import zipfile

from flask import Flask, request, jsonify, make_response, abort, json

from cuckoo.common.config import config, parse_options
from cuckoo.common.files import Files, Folders
from cuckoo.common.utils import parse_bool, constant_time_compare
from cuckoo.core.database import Database, Task
from cuckoo.core.database import TASK_REPORTED, TASK_COMPLETED, TASK_RUNNING
from cuckoo.core.rooter import rooter
from cuckoo.core.submit import SubmitManager
from cuckoo.misc import cwd, version, decide_cwd, Pidfile

log = logging.getLogger(__name__)
db = Database()
sm = SubmitManager()

# Initialize Flask app.
app = Flask(__name__)

def json_error(status_code, message):
    """Return a JSON object with a HTTP error code."""
    r = jsonify(message=message)
    r.status_code = status_code
    return r

def shutdown_server():
    """Shutdown API werkzeug server"""
    shutdown = request.environ.get("werkzeug.server.shutdown")
    if shutdown:
        shutdown()
        return True
    else:
        return False

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
    clock = request.form.get("clock", None)

    memory = parse_bool(request.form.get("memory", 0))
    unique = parse_bool(request.form.get("unique", 0))
    enforce_timeout = parse_bool(request.form.get("enforce_timeout", 0))

    content = data.read()
    if unique and db.find_sample(sha256=hashlib.sha256(content).hexdigest()):
        return json_error(400, "This file has already been submitted")

    temp_file_path = Files.temp_named_put(content, data.filename)

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

@app.route("/tasks/create/submit", methods=["POST"])
@app.route("/v1/tasks/create/submit", methods=["POST"])
def tasks_create_submit():
    files = []
    for f in request.files.getlist("file") + request.files.getlist("files"):
        files.append({
            # The pseudo-file "f" has a read() method so passing it along to
            # the Submit Manager as-is should be fine.
            "name": f.filename, "data": f,
        })

    if files:
        submit_type = "files"
    elif request.form.get("strings"):
        submit_type = "strings"
        strings = request.form["strings"].split("\n")
    else:
        return json_error(500, "No files or strings have been given!")

    # Default options.
    options = {
        "procmemdump": "yes",
    }
    options.update(parse_options(request.form.get("options", "")))

    submit_id = sm.pre(
        submit_type, files or strings, sm.translate_options_to(options)
    )
    if not submit_id:
        return json_error(500, "Error creating Submit entry")

    files, errors, options = sm.get_files(submit_id, astree=True)

    options["full-memory-dump"] = parse_bool(
        request.form.get("memory", config("cuckoo:cuckoo:memory_dump"))
    )
    options["enforce-timeout"] = parse_bool(
        request.form.get("enforce_timeout", 0)
    )

    def selected(files, arcname=None):
        ret = []
        for entry in files:
            if entry.get("selected"):
                entry["arcname"] = arcname
                ret.append(entry)
            ret += selected(entry["children"], arcname or entry["filename"])
        return ret

    task_ids = sm.submit(submit_id, {
        "global": {
            "timeout": request.form.get("timeout", ""),
            "priority": request.form.get("priority", 1),
            "tags": request.form.get("tags", None),
            "custom": request.form.get("custom", ""),
            "owner": request.form.get("owner", ""),
            "clock": request.form.get("clock", None),
            "options": options,
        },
        "file_selection": selected(files),
    })
    return jsonify(submit_id=submit_id, task_ids=task_ids, errors=errors)

@app.route("/tasks/list")
@app.route("/v1/tasks/list")
@app.route("/tasks/list/<int:limit>")
@app.route("/v1/tasks/list/<int:limit>")
@app.route("/tasks/list/<int:limit>/<int:offset>")
@app.route("/v1/tasks/list/<int:limit>/<int:offset>")
@app.route("/tasks/sample/<int:sample_id>")
@app.route("/v1/tasks/sample/<int:sample_id>")
def tasks_list(limit=None, offset=None, sample_id=None):
    response = {}

    response["tasks"] = []

    completed_after = request.args.get("completed_after")
    if completed_after:
        completed_after = datetime.datetime.fromtimestamp(
            int(completed_after)
        )

    owner = request.args.get("owner")
    status = request.args.get("status")

    tasks = db.list_tasks(
        limit=limit, details=True, offset=offset,
        completed_after=completed_after, owner=owner,
        status=status, sample_id=sample_id,
        order_by=Task.completed_on.asc()
    )

    for row in tasks:
        task = row.to_dict(dt=True)

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
    if not task:
        return json_error(404, "Task not found")

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
    if not new_task_id:
        return json_error(
            500, "An error occurred while trying to reschedule the task"
        )

    response["status"] = "OK"
    response["task_id"] = new_task_id
    return jsonify(response)

@app.route("/tasks/delete/<int:task_id>")
@app.route("/v1/tasks/delete/<int:task_id>")
def tasks_delete(task_id):
    response = {}

    task = db.view_task(task_id)
    if not task:
        return json_error(404, "Task not found")

    if task.status == TASK_RUNNING:
        return json_error(
            500, "The task is currently being processed, cannot delete"
        )

    if not db.delete_task(task_id):
        return json_error(
            500, "An error occurred while trying to delete the task"
        )

    Folders.delete(cwd("storage", "analyses", "%d" % task_id))
    response["status"] = "OK"
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
        report_path = cwd(
            "storage", "analyses", "%d" % task_id, "reports",
            formats[report_format.lower()]
        )
    elif report_format.lower() in bz_formats:
        bzf = bz_formats[report_format.lower()]
        srcdir = cwd("storage", "analyses", "%d" % task_id)
        s = io.BytesIO()

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

    if not os.path.exists(report_path):
        return json_error(404, "Report not found")

    elements = request.args.get("elements")
    if report_format.lower() == "json":
        report_content = open(report_path, "rb").read()
        if elements is not None:
            elements_content = json.loads(report_content).get(elements)
            if elements_content is None:
                return json_error(404, "'{0}' not found".format(elements))
            else:
                response = make_response(json.dumps(elements_content))
                response.headers["Content-Type"] = "application/json"
                return response

        response = make_response(report_content)
        response.headers["Content-Type"] = "application/json"
        return response
    else:
        if elements is not None:
            return json_error(404, "Get specific field is not available in HTML format,"\
                              " try again with JSON format")
        return open(report_path, "rb").read()

@app.route("/tasks/screenshots/<int:task_id>")
@app.route("/v1/tasks/screenshots/<int:task_id>")
@app.route("/tasks/screenshots/<int:task_id>/<screenshot>")
@app.route("/v1/tasks/screenshots/<int:task_id>/<screenshot>")
def task_screenshots(task_id=0, screenshot=None):
    folder_path = cwd("storage", "analyses", "%s" % task_id, "shots")

    if not os.path.exists(folder_path):
        return json_error(404, "Task not found")

    if screenshot:
        screenshot_name = "%s.jpg" % screenshot
        screenshot_path = os.path.join(folder_path, screenshot_name)
        if not os.path.exists(screenshot_path):
            return json_error(404, "Screenshot not found!")

        # TODO: Add content disposition.
        response = make_response(open(screenshot_path, "rb").read())
        response.headers["Content-Type"] = "image/jpeg"
        return response
    else:
        zip_data = io.BytesIO()
        with zipfile.ZipFile(zip_data, "w", zipfile.ZIP_STORED) as zip_file:
            for shot_name in os.listdir(folder_path):
                zip_file.write(os.path.join(folder_path, shot_name), shot_name)

        # TODO: Add content disposition.
        response = make_response(zip_data.getvalue())
        response.headers["Content-Type"] = "application/zip"
        return response

@app.route("/tasks/rereport/<int:task_id>")
def rereport(task_id):
    task = db.view_task(task_id)
    if not task:
        return json_error(404, "Task not found")

    if task.status == TASK_REPORTED:
        db.set_status(task_id, TASK_COMPLETED)
        return jsonify(success=True)

    return jsonify(success=False)

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

    if not sample:
        return json_error(404, "File not found")

    response["sample"] = sample.to_dict()
    return jsonify(response)

@app.route("/files/get/<sha256>")
@app.route("/v1/files/get/<sha256>")
def files_get(sha256):
    file_path = cwd("storage", "binaries", sha256)
    if not os.path.exists(file_path):
        return json_error(404, "File not found")

    response = make_response(open(file_path, "rb").read())
    response.headers["Content-Type"] = \
        "application/octet-stream; charset=UTF-8"
    return response

@app.route("/pcap/get/<int:task_id>")
@app.route("/v1/pcap/get/<int:task_id>")
def pcap_get(task_id):
    file_path = cwd("storage", "analyses", "%s" % task_id, "dump.pcap")
    if not os.path.exists(file_path):
        return json_error(404, "File not found")

    try:
        # TODO This could be a big file, so eventually we have to switch
        # to app.send_static_file() instead.
        response = make_response(open(file_path, "rb").read())
        response.headers["Content-Type"] = \
            "application/octet-stream; charset=UTF-8"
        return response
    except:
        return json_error(500, "An error occurred while reading PCAP")

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
    if not machine:
        return json_error(404, "Machine not found")

    response["machine"] = machine.to_dict()
    return jsonify(response)

@app.route("/cuckoo/status")
@app.route("/v1/cuckoo/status")
def cuckoo_status():
    # In order to keep track of the diskspace statistics of the temporary
    # directory we create a temporary file so we can statvfs() on that.
    temp_file = Files.temp_put("")

    paths = dict(
        binaries=cwd("storage", "binaries"),
        analyses=cwd("storage", "analyses"),
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
            memavail = int(values["MemAvailable"])
            memtotal = int(values["MemTotal"])
            memory = 100 - 100.0 * memavail / memtotal
        else:
            memory = memavail = memtotal = None
    else:
        memory = memavail = memtotal = None

    try:
        cpu_core_count = multiprocessing.cpu_count()
    except NotImplementedError:
        cpu_core_count = None

    response = dict(
        version=version,
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
        cpu_count=cpu_core_count,
        memory=memory,
        memavail=memavail,
        memtotal=memtotal,
        processes=Pidfile.get_active_pids()
    )

    return jsonify(response)

@app.route("/memory/list/<int:task_id>")
def memorydumps_list(task_id):
    folder_path = cwd("storage", "analyses", "%s" % task_id, "memory")

    if not os.path.exists(folder_path):
        return json_error(404, "Memory dump not found")

    memory_files = []
    for subdir, dirs, files in os.walk(folder_path):
        for filename in files:
            memory_files.append(filename.replace(".dmp", ""))

    if not memory_files:
        return json_error(404, "Memory dump not found")

    return jsonify({"dump_files": memory_files})

@app.route("/memory/get/<int:task_id>/<pid>")
def memorydumps_get(task_id, pid=None):
    folder_path = cwd("storage", "analyses", "%s" % task_id, "memory")

    if not os.path.exists(folder_path) or not pid:
        return json_error(404, "Memory dump not found")

    pid_path = os.path.join(folder_path, "%s.dmp" % pid)
    if not os.path.exists(pid_path):
        return json_error(404, "Memory dump not found")

    response = make_response(open(pid_path, "rb").read())
    response.headers["Content-Type"] = \
        "application/octet-stream; charset=UTF-8"
    return response

@app.route("/vpn/status")
def vpn_status():
    status = rooter("vpn_status")
    if status is None:
        return json_error(500, "Rooter not available")

    return jsonify({"vpns": status})

@app.route("/exit")
def exit_api():
    """Shuts down the server if in debug mode and
    using the werkzeug server"""
    if not app.debug:
        return json_error(403, "This call can only be used in debug mode")

    if not shutdown_server():
        return json_error(
            500, "Shutdown only possible if using werkzeug server"
        )
    else:
        return jsonify(message="Server stopped")

@app.errorhandler(401)
def api_auth_required(error):
    return json_error(
        401, "Authentication in the form of an "
        "'Authorization: Bearer <TOKEN>' header is required"
    )

@app.before_request
def check_authentication():
    token = config("cuckoo:cuckoo:api_token")
    if token:
        expect = "Bearer " + token
        auth = request.headers.get("Authorization")
        if not constant_time_compare(auth, expect):
            abort(401)

def cuckoo_api(hostname, port, debug):
    if not config("cuckoo:cuckoo:api_token"):
        log.warning(
            "It is strongly recommended to enable API authentication to "
            "protect against unauthorized access and CSRF attacks."
        )
        log.warning("Please check the API documentation for more information.")
    app.run(host=hostname, port=port, debug=debug)

if os.environ.get("CUCKOO_APP") == "api":
    decide_cwd(exists=True)
    Database().connect()
