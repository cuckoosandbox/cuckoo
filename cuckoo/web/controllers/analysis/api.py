# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pymongo
import calendar
from datetime import datetime, timedelta

import dateutil.relativedelta
from sqlalchemy import asc
from django.conf import settings
from django.http import JsonResponse

from cuckoo.core.database import Database, Task
from bin.utils import api_post, json_error_response
from controllers.analysis.analysis import AnalysisController

results_db = settings.MONGO

class AnalysisApi:
    @api_post
    def recent(request, body):
        limit = body.get("limit", 50)
        offset = body.get("offset", 0)

        # filters
        cats = body.get("cats")
        packs = body.get("packs")
        score_range = body.get("score", None)

        filters = {}

        if cats:
            filters["info.category"] = {"$in": cats}

        if packs:
            filters["info.package"] = {"$in": packs}

        if isinstance(score_range, (str, unicode)) and score_range != "":
            if "-" not in score_range:
                return json_error_response("faulty score")

            score_min, score_max = score_range.split("-", 1)

            try:
                score_min = int(score_min)
                score_max = int(score_max)

                if score_min < 0 or score_min > 10 or score_max < 0 or score_max > 10:
                    return json_error_response("faulty score")

                filters["info.score"] = {"$gte": score_min, "$lte": score_max}
            except:
                return json_error_response("faulty score")

        # @TO-DO: Use a mongodb abstraction class if there is one
        cursor = results_db.analysis.find(
            filters, sort=[("_id", pymongo.DESCENDING)]
        ).limit(limit).skip(offset)

        tasks = []
        for row in cursor:
            tasks.append({
                "ended": row["info"]["ended"],
                "score": row["info"].get("score"),
                "id": row["info"]["id"]
            })

        db = Database()

        if tasks:
            q = db.Session().query(Task)
            q = q.filter(Task.id.in_([t["id"] for t in tasks]))

            for task_sql in q.all():
                for task_mongo in [t for t in tasks if t["id"] == task_sql.id]:
                    if task_sql.sample:
                        task_mongo["sample"] = task_sql.sample.to_dict()
                    else:
                        task_mongo["sample"] = {}

                    if task_sql.category == "file":
                        task_mongo["filename_url"] = os.path.basename(task_sql.target)
                    elif task_sql.category == "url":
                        task_mongo["filename_url"] = task_sql.target

                    task_mongo.update(task_sql.to_dict())

        # Fetch remaining tasks that were not completed
        q = db.Session().query(Task)
        q = q.filter(Task.status != "reported")
        if offset == 0:
            for task_sql in q.all():
                tasks.append({
                    "id": task_sql.id,
                    "filename_url": "-",
                    "added_on": task_sql.added_on,
                    "status": task_sql.status,
                    "score": 0,
                    "category": task_sql.category
                })

        tasks = sorted(tasks, key=lambda k: k["id"], reverse=True)

        return JsonResponse(tasks, safe=False)

    @api_post
    def recent_stats(request, body):
        """
        Fetches the number of analysis over a
        given period for the "failed" and
        "successful" states. Values are
        returned in months.
        :param days: integer; the amount of days to go back in time starting from today.
        :return: A list of months and their statistics
        """
        now = datetime.now()
        days = body.get("days", 365)

        if not isinstance(days, int):
            return json_error_response("parameter \"days\" not an integer")

        db = Database()
        q = db.Session().query(Task)
        q = q.filter(Task.added_on.between(now - timedelta(days=days), now))
        q = q.order_by(asc(Task.added_on))
        tasks = q.all()

        def _rtn_structure(start):
            _data = []

            for i in range(0, 12):
                if (now - start).total_seconds() < 0:
                    return _data

                _data.append({
                    "month": start.month,
                    "year": start.year,
                    "month_human": calendar.month_name[start.month],
                    "num": 0
                })

                start = start + dateutil.relativedelta.relativedelta(months=1)

            return _data

        if not tasks:
            return json_error_response("No tasks found")

        data = {
            "analysis": _rtn_structure(tasks[0].added_on),
            "failed": _rtn_structure(tasks[0].added_on)
        }

        for task in tasks:
            added_on = task.added_on
            success = "analysis" if task.status == "reported" else "failed"

            entry = next((z for z in data[success] if
                          z["month"] == added_on.month and
                          z["year"] == added_on.year), None)
            if entry:
                entry["num"] += 1

        return JsonResponse({"status": True, "data": data}, safe=False)

    @api_post
    def behavior_get_processes(request, body):
        task_id = body.get("task_id", None)
        if not task_id:
            return json_error_response("missing task_id")

        report = AnalysisController.get_report(task_id)

        plist = {
            "data": [],
            "status": True
        }

        for process in report["analysis"].get("behavior", {}).get("generic", []):
            plist["data"].append({
                "process_name": process["process_name"],
                "pid": process["pid"]
            })

        # sort returning list of processes by their name
        plist["data"] = sorted(plist["data"], key=lambda k: k["process_name"])

        return JsonResponse(plist, safe=False)

    @staticmethod
    def behavior_get_watcherlist():
        return {
            "files":
                ["file_opened", "file_read"],
            "registry":
                ["regkey_opened", "regkey_written", "regkey_read"],
            "mutexes":
                ["mutex"],
            "directories":
                ["directory_created", "directory_removed", "directory_enumerated"],
            "processes":
                ["command_line", "dll_loaded"],
        }

    @api_post
    def behavior_get_watchers(request, body):
        task_id = body.get("task_id", None)
        pid = body.get("pid", None)

        if not task_id or not pid:
            return json_error_response("missing task_id or pid")

        report = AnalysisController.get_report(task_id)
        behavior_generic = report["analysis"]["behavior"]["generic"]
        process = [z for z in behavior_generic if z["pid"] == pid]

        if not process:
            return json_error_response("missing pid")
        else:
            process = process[0]

        data = {}
        for category, watchers in AnalysisApi.behavior_get_watcherlist().iteritems():
            for watcher in watchers:
                if watcher in process["summary"]:
                    if category not in data:
                        data[category] = [watcher]
                    else:
                        data[category].append(watcher)

        return JsonResponse({"status": True, "data": data}, safe=False)

    @api_post
    def behavior_get_watcher(request, body):
        task_id = body.get("task_id", None)
        pid = body.get("pid", None)
        watcher = body.get("watcher", None)
        limit = body.get("limit", None)
        offset = body.get("offset", None)

        if not task_id or not watcher or not pid:
            return json_error_response("missing task_id, watcher, and/or pid")

        report = AnalysisController.get_report(task_id)
        behavior_generic = report["analysis"]["behavior"]["generic"]
        process = [z for z in behavior_generic if z["pid"] == pid]

        if not process:
            return json_error_response("supplied pid not found")
        else:
            process = process[0]

        summary = process["summary"]

        if watcher not in summary:
            return json_error_response("supplied watcher not found")

        if offset:
            summary[watcher] = summary[watcher][offset:]

        if limit:
            summary[watcher] = summary[watcher][:limit]

        return JsonResponse({"status": True, "data": summary[watcher]}, safe=False)
