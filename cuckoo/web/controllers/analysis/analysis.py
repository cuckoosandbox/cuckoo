# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import os
import pymongo

from django.http import Http404

from cuckoo.core.database import Database, TASK_PENDING
from cuckoo.common.mongo import mongo

db = Database()

class AnalysisController:
    @staticmethod
    def task_info(task_id):
        if not isinstance(task_id, int):
            raise Exception("Task ID should be integer")
        data = {}

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

            data["task"] = entry
        else:
            return Exception("Task not found")

        return data

    @staticmethod
    def get_recent(limit=50, offset=0):
        db = Database()
        tasks_files = db.list_tasks(
            limit=limit,
            offset=offset,
            category="file",
            not_status=TASK_PENDING)

        tasks_urls = db.list_tasks(
            limit=limit,
            offset=offset,
            category="url",
            not_status=TASK_PENDING)

        data = []
        if tasks_files:
            for task in tasks_files:
                new = task.to_dict()
                new["sample"] = db.view_sample(new["sample_id"]).to_dict()

                filename = os.path.basename(new["target"])
                new.update({"filename": filename})

                if db.view_errors(task.id):
                    new["errors"] = True

                data.append(new)

        if tasks_urls:
            for task in tasks_urls:
                new = task.to_dict()

                if db.view_errors(task.id):
                    new["errors"] = True

                data.append(new)

        return data

    @staticmethod
    def get_report(task_id):
        report = AnalysisController._get_report(task_id)
        if not report:
            raise Http404("the specified analysis does not exist")

        data = {
            "analysis": report
        }

        dnsinfo = AnalysisController._get_dnsinfo(report)
        data.update(dnsinfo)
        return data

    @staticmethod
    def _get_report(task_id):
        return mongo.db.analysis.find_one({
            "info.id": int(task_id)
        }, sort=[("_id", pymongo.DESCENDING)])

    @staticmethod
    def get_reports(filters):
        cursor = mongo.db.analysis.find(
            filters, sort=[("_id", pymongo.DESCENDING)]
        )
        return [report for report in cursor]

    @staticmethod
    def _get_dnsinfo(report):
        """Create DNS information dicts by domain and ip"""

        if "network" in report and "domains" in report["network"]:
            domainlookups = dict((i["domain"], i["ip"]) for i in report["network"]["domains"])
            iplookups = dict((i["ip"], i["domain"]) for i in report["network"]["domains"])

            for i in report["network"]["dns"]:
                for a in i["answers"]:
                    iplookups[a["data"]] = i["request"]
        else:
            domainlookups = dict()
            iplookups = dict()

        return {
            "domainlookups": domainlookups,
            "iplookups": iplookups,
        }

    @staticmethod
    def get_behavior(task_id, report=None):
        """
        Returns behavioral information about an analysis
        sorted by category (files, registry, mutexes, etc)
        @param task_id: The analysis ID
        @param report: JSON analysis blob that is stored in MongoDB (results.json)
        @return: behavioral information as a dict
        """
        data = {}
        if not report:
            report = AnalysisController.get_report(task_id)["analysis"]
        procs = AnalysisController.behavior_get_processes(task_id, report)

        for proc in procs["data"]:
            pid = proc["pid"]
            pname = proc["process_name"]
            pdetails = None
            for p in report["behavior"]["generic"]:
                if p["pid"] == pid:
                    pdetails = p
            if not pdetails:
                continue

            watchers = AnalysisController.behavior_get_watchers(
                task_id, pid=pid, report=report)

            for category, events in watchers.iteritems():
                if not data.has_key(category):
                    data[category] = {}
                if not data[category].has_key(pid):
                    data[category][pname] = {
                        "pid": pid,
                        "process_name": pname,
                        "events": {}
                    }

                for event in events:
                    if not data[category][pname]["events"].has_key(event):
                        data[category][pname]["events"][event] = []
                    for _event in pdetails["summary"][event]:
                        data[category][pname]["events"][event].append(_event)

        return data

    @staticmethod
    def behavior_get_processes(task_id, report=None):
        if not task_id:
            raise Exception("missing task_id")
        if not report:
            report = AnalysisController.get_report(task_id)["analysis"]

        data = {
            "data": [],
            "status": True
        }

        for process in report.get("behavior", {}).get("generic", []):
            data["data"].append({
                "process_name": process["process_name"],
                "pid": process["pid"]
            })

        # sort returning list of processes by their name
        data["data"] = sorted(data["data"], key=lambda k: k["process_name"])

        return data

    @staticmethod
    def behavior_get_watchers(task_id, pid, report=None):
        if not task_id or not pid:
            raise Exception("missing task_id or pid")
        if not report:
            report = AnalysisController.get_report(task_id)["analysis"]

        behavior_generic = report["behavior"]["generic"]
        process = [z for z in behavior_generic if z["pid"] == pid]

        if not process:
            raise Exception("missing pid")
        else:
            process = process[0]

        data = {}
        for category, watchers in AnalysisController.behavioral_mapping().iteritems():
            for watcher in watchers:
                if watcher in process["summary"]:
                    if category not in data:
                        data[category] = [watcher]
                    else:
                        data[category].append(watcher)

        return data

    @staticmethod
    def behavior_get_watcher(task_id, pid, watcher, limit=None, offset=0, report=None):
        if not task_id or not watcher or not pid:
            raise Exception("missing task_id, watcher, and/or pid")
        if not report:
            report = AnalysisController.get_report(task_id)["analysis"]

        behavior_generic = report["behavior"]["generic"]
        process = [z for z in behavior_generic if z["pid"] == pid]

        if not process:
            raise Exception("supplied pid not found")
        else:
            process = process[0]

        summary = process["summary"]

        if watcher not in summary:
            raise Exception("supplied watcher not found")
        if offset:
            summary[watcher] = summary[watcher][offset:]
        if limit:
            summary[watcher] = summary[watcher][:limit]

        return summary[watcher]

    @staticmethod
    def behavioral_mapping():
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

    @staticmethod
    def signatures(task_id, signatures=None):
        """Returns an OrderedDict containing a lists with signatures based on severity"""
        if not task_id:
            raise Exception("missing task_id")
        if not signatures:
            signatures = AnalysisController.get_report(task_id)["signatures"]

        data = collections.OrderedDict()
        for signature in signatures:
            severity = signature["severity"]
            if severity > 3:
                severity = 3
            if not data.has_key(severity):
                data[severity] = []
            data[severity].append(signature)
        return data
