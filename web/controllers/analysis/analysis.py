# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import zipfile
import json
from StringIO import StringIO

import pymongo
from django.conf import settings
from django.views.decorators.http import require_safe
from django.shortcuts import render, redirect
from django.http import Http404

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_COMPLETED
from lib.cuckoo.common.utils import versiontuple
from lib.cuckoo.common.constants import LATEST_HTTPREPLAY

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
    def get_export(request, task_id):
        taken_dirs = request.POST.getlist("dirs")
        taken_files = request.POST.getlist("files")

        if not taken_dirs and not taken_files:
            return render(request, "error.html", {
                "error": "Please select at least one directory or file to be exported."
            })

        report = AnalysisController.get_report(task_id)
        path = report["info"]["analysis_path"]

        # Creating an analysis.json file with basic information about this
        # analysis. This information serves as metadata when importing a task.
        analysis_path = os.path.join(path, "analysis.json")
        with open(analysis_path, "w") as outfile:
            report["target"].pop("file_id", None)
            json.dump({"target": report["target"]}, outfile, indent=4)

        f = StringIO()

        # Creates a zip file with the selected files and directories of the task.
        zf = zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED)

        for dirname, subdirs, files in os.walk(path):
            if os.path.basename(dirname) == task_id:
                for filename in files:
                    if filename in taken_files:
                        zf.write(os.path.join(dirname, filename), filename)
            if os.path.basename(dirname) in taken_dirs:
                for filename in files:
                    zf.write(os.path.join(dirname, filename),
                             os.path.join(os.path.basename(dirname), filename))

        zf.close()

        return f

    @staticmethod
    def get_report(task_id):
        report = AnalysisController._get_report(task_id)
        if not report:
            raise Http404("The specified analysis does not exist")

        data = {
            'analysis': report
        }

        dnsinfo = AnalysisController._get_dnsinfo(report)
        data.update(dnsinfo)

        httpreplay = AnalysisController._get_httpreplay(report)
        data.update(httpreplay)

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
        # Creating dns information dicts by domain and ip.
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
            'domainlookups': domainlookups,
            'iplookups': iplookups
        }

    @staticmethod
    def _get_httpreplay(report):
        if "http_ex" in report["network"] or "https_ex" in report["network"]:
            HAVE_HTTPREPLAY = True
        else:
            HAVE_HTTPREPLAY = False

        try:
            import httpreplay
            httpreplay_version = getattr(httpreplay, "__version__", None)
        except ImportError:
            httpreplay_version = None

        # Is this version of httpreplay deprecated?
        deprecated = httpreplay_version and \
            versiontuple(httpreplay_version) < versiontuple(LATEST_HTTPREPLAY)

        return {
            "httpreplay": {
                "have": HAVE_HTTPREPLAY,
                "deprecated": deprecated,
                "current_version": httpreplay_version,
                "latest_version": LATEST_HTTPREPLAY,
            }
        }
