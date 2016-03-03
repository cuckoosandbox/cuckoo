# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile
import time

from flask import Blueprint, jsonify, request, send_file

import settings

from distributed.db import db, Node, Task, Machine, NodeStatus
from distributed.api import list_machines

blueprint = Blueprint("api", __name__)
routes = ["/api", "/api/v1"]

def json_error(status_code, message, *args):
    r = jsonify(success=False, message=message % args if args else message)
    r.status_code = status_code
    return r

def node_url(ip=None, url=None):
    if ip is not None:
        return "http://%s:8090/" % ip
    return url

@blueprint.route("/node")
@blueprint.route("/node/<string:name>")
def node_get(name=None):
    nodes = {}
    for node in Node.query.all():
        if name and node.name != name:
            continue

        machines = []
        for machine in node.machines.all():
            machines.append(dict(
                name=machine.name,
                platform=machine.platform,
                tags=machine.tags,
            ))

        nodes[node.name] = dict(
            enabled=node.enabled,
            name=node.name,
            url=node.url,
            mode=node.mode,
            machines=machines,
        )

    # In the "workers" mode we only report the names of each enabled node.
    if request.args.get("mode") == "workers":
        workers = []
        for node in nodes.values():
            if not node["enabled"]:
                continue

            workers.append(node["name"])

        return " ".join(sorted(workers))

    return jsonify(success=True, nodes=nodes)

@blueprint.route("/node", methods=["POST"])
def node_post():
    if "name" not in request.form:
        return json_error(404, "Missing node name")

    if "ip" not in request.form and "url" not in request.form:
        return json_error(404, "Missing IP address or direct URL")

    if Node.query.filter_by(name=request.form["name"]).first():
        return json_error(409, "There is already a node with this name")

    url = node_url(ip=request.form.get("ip"), url=request.form.get("url"))
    node = Node(name=request.form["name"], url=url,
                mode=request.form.get("mode", "normal"))

    try:
        machines = list_machines(url)
    except Exception as e:
        return json_error(404, "Error connecting to Cuckoo node: %s", e)

    for machine in machines:
        m = Machine(name=machine["name"], platform=machine["platform"],
                    tags=machine["tags"])
        node.machines.append(m)
        db.session.add(m)

    db.session.add(node)
    db.session.commit()
    return jsonify(success=True, machines=machines)

@blueprint.route("/node/<string:name>", methods=["PUT"])
def node_put(name):
    node = Node.query.filter_by(name=name).first()
    if not node:
        return json_error(404, "No such node")

    if "name" in request.form:
        node.name = request.form["name"]

    if "ip" in request.form or "url" in request.form:
        node.url = \
            node_url(ip=request.form.get("ip"), url=request.form.get("url"))

    if "enabled" in request.form:
        node.enabled = bool(int(request.form["enabled"]))

    db.session.commit()
    return jsonify(success=True)

@blueprint.route("/node/<string:name>", methods=["DELETE"])
def node_delete(name):
    node = Node.query.filter_by(name=name).first()
    if not node:
        return json_error(404, "No such node")

    node.enabled = False
    db.session.commit()
    return jsonify(success=True)

@blueprint.route("/task")
def task_list():
    offset = request.args.get("offset")
    limit = request.args.get("limit")
    finished = request.args.get("finished")
    status = request.args.get("status")
    owner = request.args.get("owner")
    priority = request.args.get("priority")

    if finished is not None and status is not None:
        return json_error(400, "Do not combine finished and status. "
                               "Finished has been deprecated.")

    q = Task.query.order_by(Task.id)

    if finished is not None:
        if int(finished):
            q = q.filter_by(status=Task.FINISHED)
        else:
            q = q.filter(Task.status.in_((Task.PENDING, Task.ASSIGNED,
                                          Task.PROCESSING)))

    if status is not None:
        q = q.filter_by(status=status)

    if owner:
        q = q.filter_by(owner=owner)

    if priority:
        q = q.filter_by(priority=int(priority))

    if offset is not None:
        q = q.offset(int(offset))

    if limit is not None:
        q = q.limit(int(limit))

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
    return jsonify(success=True, tasks=tasks)

@blueprint.route("/task", methods=["POST"])
def task_post():
    if "file" not in request.files:
        return json_error(404, "No file has been provided")

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

    fd, path = tempfile.mkstemp(dir=settings.samples_directory)
    f.save(path)
    os.close(fd)

    task = Task(path=path, filename=os.path.basename(f.filename), **args)
    db.session.add(task)
    db.session.commit()
    return jsonify(success=True, task_id=task.id)

@blueprint.route("/task/<int:task_id>")
def task_get(task_id):
    task = Task.query.get(task_id)
    if task is None:
        return json_error(404, "Task not found")

    return jsonify(success=True, tasks={task.id: dict(
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
        node_id=task.node_id,
        task_id=task.task_id,
        status=task.status,
    )})

@blueprint.route("/task/<int:task_id>", methods=["DELETE"])
def task_delete(task_id):
    task = Task.query.get(task_id)
    if task is None:
        return json_error(404, "Task not found")

    # Remove all available reports.
    dirpath = os.path.join(settings.reports_directory, "%d" % task_id)
    for report_format in settings.report_formats:
        path = os.path.join(dirpath, "report.%s" % report_format)
        if os.path.isfile(path):
            os.unlink(path)

    # Remove the sample related to this task (if there's any).
    if task.path and os.path.isfile(task.path):
        os.unlink(task.path)

    # If the task has been finalized then we set the status as deleted. But
    # otherwise we just delete the entry altogether, as it'd incorrectly
    # reflect the amount of processed samples in our database.
    if task.status == Task.PENDING:
        db.session.delete(task)
    else:
        task.status = Task.DELETED

    db.session.commit()
    return jsonify(success=True)

@blueprint.route("/report/<int:task_id>")
@blueprint.route("/report/<int:task_id>/<string:report_format>")
def report_get(task_id, report_format="json"):
    task = Task.query.get(task_id)
    if not task:
        return json_error(404, "Task not found")

    if task.status == Task.DELETED:
        return json_error(404, "Task report has been deleted")

    if task.status != Task.FINISHED:
        return json_error(420, "Task not finished yet")

    report_path = os.path.join(settings.reports_directory,
                               "%d" % task_id, "report.%s" % report_format)
    if not os.path.isfile(report_path):
        return json_error(404, "Report format not found")

    return send_file(report_path)

@blueprint.route("/pcap/<int:task_id>")
def pcap_get(task_id):
    task = Task.query.get(task_id)
    if not task:
        return json_error(404, "Task not found")

    if task.status == Task.DELETED:
        return json_error(404, "Task files has been deleted")

    if task.status != Task.FINISHED:
        return json_error(420, "Task not finished yet")

    pcap_path = os.path.join(settings.reports_directory,
                             "%s" % task_id, "dump.pcap")
    if not os.path.isfile(pcap_path):
        return json_error(404, "Pcap file not found")

    return send_file(pcap_path)

@blueprint.route("/status")
def status_get():
    paths = dict(
        reports=settings.reports_directory,
        samples=settings.samples_directory,
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

    dist = {
        "diskspace": diskspace,
    }

    statuses = {}
    for node in Node.query.filter_by(enabled=True).all():
        q = NodeStatus.query.filter_by(name=node.name)
        status = q.order_by(NodeStatus.timestamp.desc()).first()
        if status:
            statuses[node.name] = status.status

    q = NodeStatus.query.filter_by(name="dist.scheduler")
    tasks = q.order_by(NodeStatus.timestamp.desc()).first()
    if tasks:
        tasks = tasks.status

    return jsonify(success=True, nodes=statuses, tasks=tasks,
                   dist=dist, timestamp=int(time.time()))
