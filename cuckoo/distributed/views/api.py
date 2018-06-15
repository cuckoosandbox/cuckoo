# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import os
import sqlalchemy
import tempfile
import time

from flask import Blueprint, jsonify, request, send_file

from cuckoo.distributed.api import list_machines
from cuckoo.distributed.db import db, Node, Task, Machine, NodeStatus
from cuckoo.distributed.misc import settings, StatsCache

blueprint = Blueprint("api", __name__)
routes = ["/api", "/api/v1"]

null = None

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
        node.url = node_url(
            ip=request.form.get("ip"), url=request.form.get("url")
        )

    if "enabled" in request.form:
        node.enabled = bool(int(request.form["enabled"]))

    db.session.commit()
    return jsonify(success=True)

@blueprint.route("/node/<string:name>/refresh", methods=["POST"])
def node_refresh(name):
    node = Node.query.filter_by(name=name).first()
    if not node:
        return json_error(404, "No such node")

    try:
        machines = list_machines(node.url)
    except Exception as e:
        return json_error(404, "Error connecting to Cuckoo node: %s", e)

    machines_existing = {}
    for machine in node.machines:
        machine_values = machine.name, machine.platform
        machines_existing[machine_values] = machine

    # Add new machines.
    for machine in machines:
        machine_values = machine["name"], machine["platform"]
        if machine_values in machines_existing:
            # Update the associated tags for this machine.
            machines_existing[machine_values].tags = machine["tags"]
            del machines_existing[machine_values]
            continue

        m = Machine(name=machine["name"], platform=machine["platform"],
                    tags=machine["tags"])
        node.machines.append(m)
        db.session.add(m)

    # Unlink older machines.
    for machine in machines_existing.values():
        node.machines.remove(machine)

    db.session.commit()
    return jsonify(success=True, machines=machines)

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

    kwargs = dict(
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

    if not os.path.getsize(path):
        os.remove(path)
        return json_error(404, "Provided file is empty")

    task = Task(path=path, filename=os.path.basename(f.filename), **kwargs)

    node = request.form.get("node")
    if node:
        node = Node.query.filter_by(name=node, enabled=True).first()
        if not node:
            return json_error(404, "Node not found")
        task.assign_node(node.id)

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
def task_delete(task_id, commit=True):
    task = Task.query.get(task_id)
    if task is None:
        return json_error(404, "Task not found")

    if task.status == Task.DELETED:
        return jsonify(success=False, message="Task already deleted")

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

    commit and db.session.commit()
    return jsonify(success=True)

@blueprint.route("/tasks", methods=["DELETE"])
def tasks_delete():
    for task_id in request.form.get("task_ids", "").split():
        task_delete(int(task_id), commit=False)
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

    report_path = os.path.join(
        settings.reports_directory, "%d" % task_id,
        "report.%s" % report_format
    )
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

@blueprint.route("/stats")
@blueprint.route("/stats/<string:end_date>")
@blueprint.route("/stats/<string:end_date>/<string:end_time>")
def stats_get(end_date=None, end_time=None):
    """Returns JSON containing performance metrics over time. Optionally may
    provide 'include' GET parameter for selecting specific results."""

    if end_date:
        try:
            end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            return json_error(
                500, "Given date does not match format YYYY-MM-DD"
            )
    else:
        end_date = datetime.datetime.now().replace(second=0, microsecond=0)

    if end_time:
        try:
            t = datetime.datetime.strptime(end_time, "%H:%M").time()
            end_date = datetime.datetime.combine(end_date, t)
        except ValueError:
            return json_error(
                500, "Given time does not match format HH:MM"
            )

    stat_handlers = {
        "task_completed": _summarize_task_completed,
        "task_uncompleted": _summarize_task_uncompleted,
        "vm_running": _summarize_vms_running,
        "disk_usage": _summarize_disk_usage,
        "cpu_usage": _summarize_cpu_usage,
        "memory_usage": _summarize_ram_usage,
        "amount_prio_queued": _summarize_priority_count,
        "active_processes": _get_nodes_processes
    }

    steps = {
        "hour": {
            "step": 5, "times": 12,
        },
        "day": {
            "step": 15, "times": 96,
        },
        "week": {
            "step": 60, "times": 168,
        },
        "month": {
            "step": 1440, "times": 28,
        },
    }

    handlers = stat_handlers.keys()
    if request.args.get("include"):
        handlers = request.args.get("include").split(",")
        for handler in handlers:
            if handler not in stat_handlers:
                return json_error(
                    500, "Unknown statistics key '%s'" % handler
                )

    if request.args.get("period"):
        new_steps = {}
        periods = request.args.get("period").split(",")
        for period in periods:
            if period not in steps:
                return json_error(500, "Unknown period key '%s'" % period)
            new_steps[period] = steps[period]
        steps = new_steps

    if request.args.get("nodes"):
        nodes = []
        for node in request.args.get("nodes").split(","):
            node = Node.query.filter_by(name=node).first()
            if node:
                nodes.append(node)
    else:
        nodes = Node.query.filter_by(enabled=True).all()

    statistics = {
        "nodes": [],
    }

    for node in nodes:
        statistics["nodes"].append(node.name)

    for name in handlers:
        if name in stat_handlers:
            statistics[name] = stat_handlers[name](end_date, steps, nodes)

    return jsonify(statistics)

def _summarize_task_uncompleted(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    uncompleted/queued tasks by last hour, day, week up to the given
    date"""

    result = {}
    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        max_uncompleted = 0
        result[step_name] = {
            "info": {
                "max_points": step.get("times"),
                "step_size": step.get("step"),
                "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                "finish": end_date.strftime("%Y-%m-%d %H:%M:%S")
            },
            "points": []
        }

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))

            # Find all submissions that are not completed yet/still queued.
            # If not in cache, search db
            uncompleted = StatsCache().get_stat("uncompleted", later,
                                                step.get("step"))

            if uncompleted is None:
                uncompleted = Task.query.filter(
                    Task.status < Task.FINISHED, Task.submitted <= later
                ).count()
                StatsCache().update("uncompleted", step.get("step"),
                                    set_dt=later, set_value=uncompleted)

            if uncompleted > max_uncompleted:
                max_uncompleted = uncompleted

            time_key = later.strftime("%Y-%m-%d %H:%M:%S")
            result[step_name]["points"].append({
                "datetime": time_key,
                "value": uncompleted
            })

            past = later

        result[step_name]["info"]["max"] = max_uncompleted

    return result

def _summarize_task_completed(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    completed tasks per hour, day, week up to the given
    date"""

    result = {}
    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        max_completed = 0
        result[step_name] = {
            "info": {
                "max_points": step.get("times"),
                "step_size": step.get("step"),
                "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                "finish": end_date.strftime("%Y-%m-%d %H:%M:%S")
            },
            "points": []
        }

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))

            # Find completed tasks between date ranges
            tasks = StatsCache().get_stat(
                "completed", later, step.get("step")
            )

            if tasks is None:
                tasks = Task.query.filter(
                    Task.completed >= past, Task.completed <= later
                ).count()

                StatsCache().update(
                    "completed", step.get("step"),
                    set_dt=later, set_value=tasks
                )

            if tasks > max_completed:
                max_completed = tasks

            time_key = later.strftime("%Y-%m-%d %H:%M:%S")
            result[step_name]["points"].append({
                "datetime": time_key,
                "value": tasks
            })

            past = later

        result[step_name]["info"]["max"] = max_completed

    return result

def _summarize_disk_usage(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    currently used disk space per node by last hour, day, week up to the given
    date"""

    results = {}

    # For each node, determine which storages there are and their total
    # storage volume
    storage_nodes = {}
    for node in nodes:
        node_status = NodeStatus.query.filter(
            NodeStatus.name == node.name
        ).order_by(NodeStatus.timestamp.desc()).first()

        if node_status:
            storage_nodes[node.name] = {
                disk_n: {
                    "total": val["total"]
                }
                for disk_n, val in
                node_status.status.get("diskspace").iteritems()
            }

    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        results[step_name] = {
            node.name: {
                "info": {
                    "disks": storage_nodes[node.name],
                    "max_points": step.get("times"),
                    "step_size": step.get("step"),
                    "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                    "finish": end_date.strftime("%Y-%m-%d %H:%M:%S")
                },
                "points": {}
            }
            for node in nodes
        }

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))

            for node in nodes:
                # Query for latest entry for current node in given time range
                status = StatsCache().get_stat(
                    "status", later, step.get("step"), key_prefix=node.name
                )

                if status is None:
                    q = NodeStatus.query.filter(
                        NodeStatus.name == node.name,
                        NodeStatus.timestamp >= past
                    ).order_by(NodeStatus.timestamp.asc()).first()

                    if q is not None:
                        status = q.status

                    StatsCache().update(
                        "status", step.get("step"), set_value=status,
                        set_dt=later, key_prefix=node.name
                    )

                if not status:
                    continue

                time_key = later.strftime("%Y-%m-%d %H:%M:%S")
                current = results[step_name][node.name]["points"]
                for st_name, val in status.get("diskspace").iteritems():
                    storage_name = "%s_used" % st_name

                    if storage_name not in current:
                        current[storage_name] = []

                    current[storage_name].append({
                        "datetime": time_key,
                        "value": val["used"]
                    })

            past = later

    return results

def _summarize_vms_running(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    running vms by hour, day, week up to the given
    date"""

    results = {}

    vm_count = 0
    # Determine the total current VMs
    for node in nodes:
        node_status = NodeStatus.query.filter(
            NodeStatus.name == node.name
        ).order_by(NodeStatus.timestamp.desc()).first()

        if node_status:
            vm_count += node_status.status["machines"].get("total")

    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        results[step_name] = {
            "info": {
                "max": vm_count,
                "max_points": step.get("times"),
                "step_size": step.get("step"),
                "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                "finish": end_date.strftime("%Y-%m-%d %H:%M:%S")
            },
            "points": []
        }
        max_running = 0

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))
            running = None

            for node in nodes:
                # Query for latest entry for current node in given time range
                status = StatsCache().get_stat(
                    "status", later, step.get("step"), key_prefix=node.name
                )

                if status is None:
                    q = NodeStatus.query.filter(
                        NodeStatus.name == node.name,
                        NodeStatus.timestamp >= past
                    ).order_by(NodeStatus.timestamp.asc()).first()

                    if q is not None:
                        status = q.status

                    StatsCache().update(
                        "status", step.get("step"), set_value=status,
                        set_dt=later, key_prefix=node.name
                    )

                if not status:
                    continue

                if running is None:
                    running = 0

                total_vms = status["machines"].get("total")
                running += total_vms - status["machines"].get("available")

            time_key = later.strftime("%Y-%m-%d %H:%M:%S")

            if running is not None:
                results[step_name]["points"].append({
                    "datetime": time_key,
                    "value": running
                })

            if running > max_running:
                max_running = running

            past = later

        # Check if the amount of running VMs in the past is higher than current
        # total VMs. This can happen if VMs are removed.
        if max_running > vm_count:
            vm_count = max_running

        results[step_name]["info"]["max"] = vm_count

    return results

def _summarize_cpu_usage(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    CPU usage in percent per node per hour, day, week up to the given
    date"""

    result = {}

    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        result[step_name] = {
            node.name: {
                "info": {
                    "max_points": step.get("times"),
                    "step_size": step.get("step"),
                    "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                    "finish": end_date.strftime("%Y-%m-%d %H:%M:%S"),
                    "max": 100
                },
                "points": []
            }
            for node in nodes
        }

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))

            for node in nodes:
                # Query for latest entry for current node in given time range
                status = StatsCache().get_stat(
                    "status", later, step.get("step"), key_prefix=node.name
                )

                if status is None:
                    q = NodeStatus.query.filter(
                        NodeStatus.name == node.name,
                        NodeStatus.timestamp >= past
                    ).order_by(NodeStatus.timestamp.asc()).first()

                    if q is not None:
                        status = q.status

                    StatsCache().update(
                        "status", step.get("step"), set_value=status,
                        set_dt=later, key_prefix=node.name
                    )

                if not status or not status.get("cpu_count"):
                    continue

                cpu_count = status.get("cpu_count")
                cpu_load = status.get("cpuload")

                # Use average load of last minute. See doc (os.getloadavg)
                load = int(cpu_load[0] / cpu_count * 100)

                time_key = later.strftime("%Y-%m-%d %H:%M:%S")

                result[step_name][node.name]["points"].append({
                    "datetime": time_key,
                    "value": load
                })

            past = later

    return result

def _summarize_ram_usage(end_date, steps, nodes):
    """Create a list of datetime points containing the amounts of
    RAM usage per node per hour, day, week up to the given
    date"""

    result = {}

    for step_name, step in steps.iteritems():
        past = end_date - datetime.timedelta(
            minutes=step.get("step") * step.get("times")
        )
        result[step_name] = {
            node.name: {
                "info": {
                    "max_points": step.get("times"),
                    "step_size": step.get("step"),
                    "start": past.strftime("%Y-%m-%d %H:%M:%S"),
                    "finish": end_date.strftime("%Y-%m-%d %H:%M:%S"),
                    "max": 100,
                },
                "points": [],
            }
            for node in nodes
        }

        for x in range(step.get("times")):
            later = past + datetime.timedelta(minutes=step.get("step"))

            for node in nodes:
                # Query for latest entry for current node in given time range
                status = StatsCache().get_stat(
                    "status", later, step.get("step"), key_prefix=node.name
                )

                if status is None:
                    q = NodeStatus.query.filter(
                        NodeStatus.name == node.name,
                        NodeStatus.timestamp >= past
                    ).order_by(NodeStatus.timestamp.asc()).first()

                    if q is not None:
                        status = q.status

                    StatsCache().update(
                        "status", step.get("step"), set_value=status,
                        set_dt=later, key_prefix=node.name
                    )

                if not status or status == {} or status.get("memory") is None:
                    continue

                try:
                    memory = int(status.get("memory"))
                except ValueError:
                    continue

                time_key = later.strftime("%Y-%m-%d %H:%M:%S")
                result[step_name][node.name]["points"].append({
                    "datetime": time_key,
                    "value": memory
                })

            past = later

    return result

def _summarize_priority_count(end_date, steps, nodes):
    """Create a dictionary containing the total amount of queued
    task per priority that exists"""

    # Query for total count of each priority type and sort them by
    # priority types
    prio_count = db.session.query(
        Task.priority, sqlalchemy.func.count("*")
    ).filter(
        Task.completed == null, Task.submitted <= end_date
    ).group_by(Task.priority).all()

    return {
        "info": {
            "date": end_date.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "priorities": {
            value.priority: value[1] for value in prio_count
        },
    }

def _get_nodes_processes(end_date, steps, nodes):
    """Returns the running processes per node"""

    results = {}

    for node in nodes:
        node_procs = {"cuckoo": False, "other": []}
        status = NodeStatus.query.filter(
            NodeStatus.name == node.name, NodeStatus.timestamp <= end_date
        ).order_by(NodeStatus.timestamp.desc()).first()

        if not status:
            results[node.name] = node_procs
            continue

        procs = status.status.get("processes", {})
        for proc in procs:
            if proc == "cuckoo":
                node_procs["cuckoo"] = True
            else:
                node_procs["other"].append(proc)
        results[node.name] = node_procs

    return results
