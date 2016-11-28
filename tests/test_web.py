# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import logging
import mock
import os
import tempfile

from cuckoo.core.database import Database
from cuckoo.common.files import Folders, Files
from cuckoo.misc import cwd, set_cwd
from cuckoo.processing.static import Static

logging.basicConfig(level=logging.DEBUG)

# These have to be imported after setting the django settings module
# environment variable as they're using the settings.MONGO variable.
from cuckoo.web.controllers.analysis.routes import AnalysisRoutes

CUCKOO_CONF = """
[database]
connection =
"""

REPORTING_CONF = """
[mongodb]
enabled = on

[elasticsearch]
enabled = off

[moloch]
enabled = off
"""

ROUTING_CONF = """
[routing]
route = none
internet = none
drop = off

[inetsim]
enabled = off

[tor]
enabled = off

[vpn]
enabled = off
"""

class TestWebInterface(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), ["conf", "web"])

        Files.create(cwd(), "conf/cuckoo.conf", CUCKOO_CONF)
        Files.create(cwd(), "conf/reporting.conf", REPORTING_CONF)
        Files.create(cwd(), "conf/routing.conf", ROUTING_CONF)
        Files.create(cwd(), "web/.secret_key", "A"*40)
        Files.create(cwd(), "web/local_settings.py", "")

        django.setup()
        Database().connect()

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

    def test_index(self, client):
        assert client.get("/").status_code == 200

    def test_index_post(self, client):
        assert client.post("/").status_code == 405

    def test_summary_office1(self, request):
        with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
            ac._get_report.return_value = {
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

    def test_summary_office2(self, request):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "doc",
            "target": "createproc1.docm",
        })
        s.file_path = "tests/files/createproc1.docm"

        with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
            ac._get_report.return_value = {
                "static": s.run(),
            }
            r = AnalysisRoutes.detail(request, 1, "static").content
            assert "ThisDocument" in r
            assert "Sub AutoOpen" in r
            assert "process.Create" in r
            assert "notepad.exe" in r
