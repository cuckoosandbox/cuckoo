# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import json
import mock
import os
import tempfile

from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd
from cuckoo.processing.static import Static
from cuckoo.web.controllers.analysis.routes import AnalysisRoutes
from cuckoo.web.controllers.submission.api import defaults

class TestWebInterface(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "mongodb": {
                    "enabled": True,
                },
            },
        })

        django.setup()
        Database().connect()

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

    def test_index(self, client):
        assert client.get("/").status_code == 200

    def test_index_post(self, client):
        assert client.post("/").status_code == 405

    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    def test_summary_office1(self, p, request):
        p._get_report.return_value = {
            "static": {
                "office": {
                    "macros": [
                        {
                            "filename": "MACRO FILENAME",
                            "stream": "MACRO STREAM",
                            "orig_code": "MACRO CODE OBFUSCATED",
                            "deobf": "MACRO CODE DEOBFUSCATED",
                        },
                    ],
                },
            },
        }

        r = AnalysisRoutes.detail(request, 1, "static").content
        assert "MACRO FILENAME" in r
        assert "MACRO STREAM" in r
        assert "MACRO CODE OBFUSCATED" in r
        assert "MACRO CODE DEOBFUSCATED" in r

    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    def test_summary_office2(self, p, request):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "doc",
            "target": "createproc1.docm",
        })
        s.file_path = "tests/files/createproc1.docm"

        p._get_report.return_value = {
            "static": s.run(),
        }
        r = AnalysisRoutes.detail(request, 1, "static").content
        assert "ThisDocument" in r
        assert "Sub AutoOpen" in r
        assert "process.Create" in r
        assert "notepad.exe" in r

    def test_submit_defaults(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "routing": {
                "routing": {
                    "route": "internet",
                },
                "vpn": {
                    "vpns": [
                        "france", "italy"
                    ],
                },
                "france": {
                    "description": "VPN in France",
                },
                "italy": {
                    "description": "VPN in Italy",
                },
            },
        })
        assert defaults() == {
            "machine": None,
            "network-routing": "internet",
            "package": None,
            "priority": 2,
            "timeout": 120,
            "vpns": [
                "france", "italy"
            ],
            "options": {
                "enable-services": False,
                "enforce-timeout": False,
                "full-memory-dump": False,
                "no-injection": False,
                "process-memory-dump": True,
                "simulated-human-interaction": True,
            }
        }
        buf = open(cwd("conf", "routing.conf")).read()
        assert "[italy]" in buf
        assert "[france]" in buf
        assert "vpns = france, italy" in buf

    def test_submit_api_filetree(self, client):
        SubmitManager().pre("strings", ["google.com"])
        r = client.post(
            "/submit/api/filetree/",
            json.dumps({"submit_id": 1}),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200

        obj = json.loads(r.content)
        assert obj["status"] is True
        assert obj["data"]["files"][0]["filename"] == "google.com"
        assert obj["defaults"]["priority"] == 2
        assert obj["defaults"]["options"]["process-memory-dump"] is True
