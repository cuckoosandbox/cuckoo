# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import os
import pymongo

from django.http import Http404

from cuckoo.common.mongo import mongo
from cuckoo.core.database import Database, TASK_PENDING

db = Database()

class AnalysisController:
    @staticmethod
    def task_info(task_id):
        if not isinstance(task_id, int):
            raise Exception("Task ID should be integer")

        task = db.view_task(task_id, details=True)
        if not task:
            return Http404("Task not found")

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

        if entry["category"] == "file":
            entry["target"] = os.path.basename(entry["target"])
        elif entry["category"] == "url":
            if entry["target"].startswith(("http://", "https://")):
                entry["target"] = "hxxp" + entry["target"][4:]
        elif entry["category"] == "archive":
            entry["target"] = "%s @ %s" % (
                entry["options"]["filename"],
                os.path.basename(entry["target"])
            )

        return {
            "task": entry,
        }

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
