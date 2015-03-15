# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile

from flask import Blueprint, current_app, abort, jsonify, request, send_file
from werkzeug.exceptions import HTTPException

from lib.db import db, Node, Task
from lib.api import list_machines

blueprint = Blueprint("api", __name__)

def node_url(ip=None, url=None):
    if ip is None and url is None:
        abort(404, "Node address not found")

    if ip is not None:
        return "http://%s:8090/" % ip

    return url

@blueprint.route("/node")
def node_get():
    nodes = {}
    for node in Node.query.all():
        machines = []
        for machine in node.machines.all():
            machines.append(dict(
                name=machine.name,
                platform=machine.platform,
                tags=machine.tags,
            ))

        nodes[node.name] = dict(
            name=node.name,
            url=node.url,
            machines=machines,
        )
    return jsonify(nodes=nodes)

@blueprint.route("/node", methods=["POST"])
def node_post():
    if "name" not in request.form:
        abort(404, "Missing node name")

    if Node.query.filter_by(name=request.form["name"]).first():
        abort(409, "There is already a node with this name")

    url = node_url(ip=request.form.get("ip"), url=request.form.get("url"))
    node = Node(name=request.form["name"], url=url)

    try:
        machines = list_machines(url)
    except Exception as e:
        abort(404, "Error connecting to Cuckoo node: %s" % e)

    machines = []
    for machine in machines:
        machines.append(dict(
            name=machine.name,
            platform=machine.platform,
            tags=machine.tags,
        ))
        node.machines.append(machine)
        db.session.add(machine)

    db.session.add(node)
    db.session.commit()
    return jsonify(success=True)

@blueprint.route("/task")
def task_list():
    offset = request.args.get("offset")
    limit = request.args.get("limit")
    finished = request.args.get("finished")
    owner = request.args.get("owner")

    q = Task.query

    if finished is not None:
        q = q.filter_by(finished=bool(int(finished)))

    if offset is not None:
        q = q.offset(int(offset))

    if limit is not None:
        q = q.limit(int(limit))

    if owner:
        q = q.filter_by(owner=owner)

    tasks = {}
    for task in q.all():
        tasks[task.id] = dict(
            id=task.id,
            path=task.path,
            filename=task.filename,
            package=task.package,
            timeout=task.timeout,
            priority=task.priority,
            options=task.options,
            machine=task.machine,
            platform=task.platform,
            tags=task.tags,
            custom=task.custom,
            owner=task.owner,
            memory=task.memory,
            clock=task.clock,
            enforce_timeout=task.enforce_timeout,
            task_id=task.task_id,
            node_id=task.node_id,
        )
    return jsonify(tasks=tasks)

@blueprint.route("/task", methods=["POST"])
def task_post():
    if "file" not in request.files:
        abort(404, "No file has been provided")

    args = dict(
        package=request.form.get("package"),
        timeout=request.form.get("timeout"),
        priority=request.form.get("priority", 1),
        options=request.form.get("options"),
        machine=request.form.get("machine"),
        platform=request.form.get("platform"),
        tags=request.form.get("tags"),
        custom=request.form.get("custom"),
        owner=request.form.get("owner"),
        memory=request.form.get("memory"),
        clock=request.form.get("clock"),
        enforce_timeout=request.form.get("enforce_timeout"),
    )

    f = request.files["file"]

    fd, path = tempfile.mkstemp(dir=current_app.config["SAMPLES_DIRECTORY"])
    f.save(path)
    os.close(fd)

    task = Task(path=path, filename=os.path.basename(f.filename), **args)
    db.session.add(task)
    db.session.commit()
    return jsonify(task_id=task.id)

@blueprint.route("/task/<int:task_id>")
def task_get(task_id):
    task = Task.query.get(task_id)
    if task is None:
        abort(404, "Task not found")

    return jsonify(tasks={task.id: dict(
        task_id=task.id,
        path=task.path,
        filename=task.filename,
        package=task.package,
        timeout=task.timeout,
        priority=task.priority,
        options=task.options,
        machine=task.machine,
        platform=task.platform,
        tags=task.tags,
        custom=task.custom,
        owner=task.owner,
        memory=task.memory,
        clock=task.clock,
        enforce_timeout=task.enforce_timeout,
    )})

@blueprint.route("/task/<int:task_id>", methods=["DELETE"])
def task_delete(task_id):
    task = Task.query.get(task_id)
    if task is None:
        abort(404, "Task not found")

    # Remove all available reports.
    dirpath = os.path.join(current_app.config["REPORTS_DIRECTORY"],
                           "%d" % task_id)
    for report_format in current_app.config["REPORT_FORMATS"]:
        path = os.path.join(dirpath, "report.%s" % report_format)
        if os.path.isfile(path):
            os.unlink(path)

    # Remove the sample related to this task.
    if os.path.isfile(task.path):
        os.unlink(task.path)

    # TODO Don't delete the task, but instead change its state to deleted.
    db.session.delete(task)
    db.session.commit()
    return jsonify(success=True)

class ReportNotFinished(HTTPException):
    code = 420
    description = 'Task not finished yet'

@blueprint.route("/report/<int:task_id>")
@blueprint.route("/report/<int:task_id>/<string:report_format>")
def report_get(task_id, report_format="json"):
    task = Task.query.get(task_id)
    if not task:
        abort(404, message="Task not found")

    if not task.finished:
        raise ReportNotFinished

    report_path = os.path.join(current_app.config["REPORTS_DIRECTORY"],
                               "%d" % task_id, "report.%s" % report_format)
    if not os.path.isfile(report_path):
        abort(404, message="Report format not found")

    return send_file(report_path)
