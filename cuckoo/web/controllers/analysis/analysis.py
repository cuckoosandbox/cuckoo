# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pymongo

from django.http import Http404

from cuckoo.common.mongo import mongo
from cuckoo.core.database import Database

db = Database()

class AnalysisController:
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
