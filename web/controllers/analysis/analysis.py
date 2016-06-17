# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf import settings
from django.views.decorators.http import require_safe
from django.shortcuts import render, redirect
import pymongo

from lib.cuckoo.common.utils import versiontuple
from lib.cuckoo.common.constants import LATEST_HTTPREPLAY

results_db = settings.MONGO


class AnalysisController:
    def analysis(self, request, task_id, page):
        report = self.get_report(task_id)

        if page == "summary":
            return render(request, "analysis/pages/summary/index.html", report)

    def get_report(self, task_id):
        report = self._get_report(task_id)
        data = {
            'analysis': report
        }

        dnsinfo = self._get_dnsinfo(report)
        data.update(dnsinfo)

        httpreplay = self._get_httpreplay(report)
        data.update(httpreplay)

        return data

    @staticmethod
    def _get_report(task_id):
        return results_db.analysis.find_one({
            "info.id": int(task_id)
        }, sort=[("_id", pymongo.DESCENDING)])

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
