# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

import pymongo
from django.conf import settings

from cuckoo.core.database import Database, TASK_PENDING

results_db = settings.MONGO

class AnalysisController:
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
            raise Exception("the specified analysis does not exist")

        data = {
            "analysis": report
        }

        dnsinfo = AnalysisController._get_dnsinfo(report)
        data.update(dnsinfo)
        return data

    @staticmethod
    def _get_report(task_id):
        return results_db.analysis.find_one({
            "info.id": int(task_id)
        }, sort=[("_id", pymongo.DESCENDING)])

    @staticmethod
    def get_reports(filters):
        cursor = results_db.analysis.find(filters, sort=[("_id", pymongo.DESCENDING)])
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
            "iplookups": iplookups
        }
