# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import mock
import os
import tempfile

from cuckoo.core.database import Database
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd
from cuckoo.processing.static import Static
from cuckoo.web.controllers.analysis.routes import AnalysisRoutes

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
