# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import json
import mock
import os
import pytest
import responses
import tempfile

from cuckoo.common.exceptions import CuckooFeedbackError
from cuckoo.core.database import Database
from cuckoo.core.feedback import CuckooFeedback
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
                    "enabled": True,
                    "vpns": [
                        "france", "italy"
                    ],
                },
                "inetsim": {
                    "enabled": True,
                },
                "tor": {
                    "enabled": True,
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
            "machine": [
                "cuckoo1",
            ],
            "package": None,
            "priority": 2,
            "timeout": 120,
            "routing": {
                "route": "internet",
                "inetsim": True,
                "tor": True,
                "vpns": [
                    "france", "italy",
                ],
            },
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

    def test_submit_defaults_novpn(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "routing": {
                "vpn": {
                    "enabled": False,
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
        obj = defaults()
        assert obj["routing"]["route"] == "none"
        assert obj["routing"]["vpns"] == []
        assert obj["routing"]["inetsim"] is False
        assert obj["routing"]["tor"] is False

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

    def test_submission_submit(self, client):
        r = client.get("/submit/")
        assert r.status_code == 200
        assert r.templates[0].name == "submission/submit.html"

    def test_submission_postsubmit(self, client):
        r = client.get("/submit/post/?id=1")
        assert r.status_code == 200
        assert r.templates[0].name == "submission/postsubmit.html"

    def test_submission_presubmit_valid(self, client):
        SubmitManager().pre("strings", ["google.com"])
        r = client.get("/submit/pre/1/")
        assert r.status_code == 200
        assert r.templates[0].name == "submission/presubmit.html"

    def test_submission_presubmit_invalid(self, client):
        assert client.get("/submit/pre/1/").status_code == 302

    @mock.patch("cuckoo.web.controllers.submission.routes.dropped_filepath")
    def test_submission_dropped(self, p, client):
        p.return_value = __file__
        r = client.get("/submit/1234/dropped/" + "a"*40 + "/")
        assert r.status_code == 302

        r = SubmitManager().get_files(1)
        assert len(r["files"]) == 1
        assert os.listdir(r["path"]) == [os.path.basename(__file__)]
        assert r["files"][0].filesize == os.path.getsize(__file__)

    @mock.patch("cuckoo.web.controllers.analysis.api.CuckooFeedback")
    def test_feedback_form(self, p, client):
        p.return_value.send_form.return_value = 3
        r = client.post(
            "/analysis/api/task/feedback_send/",
            json.dumps({
                "task_id": "1",
                "email": "a@b.com",
                "message": "msg",
                "name": "name",
                "company": "company",
                "include_memdump": False,
                "include_analysis": True,
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200
        assert json.loads(r.content) == {
            "status": True, "feedback_id": 3
        }

    def test_feedback_form_invalid_email(self, client):
        r = client.post(
            "/analysis/api/task/feedback_send/",
            json.dumps({
                "task_id": "1",
                "email": "a@b.com!",
                "message": "msg",
                "name": "name",
                "company": "company",
                "include_memdump": False,
                "include_analysis": True,
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 501

        obj = json.loads(r.content)
        assert obj["status"] is False
        assert "Invalid email" in obj["message"]

    def test_api_post_not_json(self, client):
        r = client.post(
            "/analysis/api/tasks/info/",
            "NOTJSON",
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 501
        assert "not JSON" in r.content

    def test_view_error_has_envvar(self, client, settings):
        """Ensure that render_template() is used in view_error()."""
        settings.DEBUG = True
        r = client.get("/analysis/search/")
        assert r.status_code == 500

class TestWebInterfaceFeedback(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "mongodb": {
                    "enabled": True,
                },
            },
            "cuckoo": {
                "feedback": {
                    "enabled": True,
                    "name": "foo bar",
                    "email": "a@b.com",
                    "company": "yes",
                },
            },
        })

        django.setup()
        Database().connect()

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

    @responses.activate
    @mock.patch("web.errors.log")
    @mock.patch("dashboard.views.render_template")
    def test_index_exception_feedback(self, p, q, client):
        responses.add(responses.POST, CuckooFeedback.endpoint, status=403)
        p.side_effect = Exception("fake exception")

        # Make Cuckoo Feedback throw an exception (by returning failure from
        # the Cuckoo Feedback backend) and catch it.
        with pytest.raises(Exception) as e:
            client.get("/dashboard/")
        e.match("fake exception")
        assert "Invalid response from" in q.warning.call_args[0][0]
        assert "403" in q.warning.call_args[0][0]

    @mock.patch("web.errors.log")
    @mock.patch("cuckoo.core.feedback.CuckooFeedbackObject")
    @mock.patch("dashboard.views.render_template")
    def test_index_exception_noanalysis(self, p, q, r, client):
        p.side_effect = Exception("fake exception")
        q.return_value.validate.side_effect = CuckooFeedbackError

        with pytest.raises(Exception) as e:
            client.get("/dashboard/")
        e.match("fake exception")

        q.return_value.add_traceback.assert_called_once()
        q.return_value.include_report_web.assert_not_called()
        q.return_value.include_analysis.assert_not_called()
        r.warning.assert_called_once()

    @mock.patch("web.errors.log")
    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    @mock.patch("cuckoo.core.feedback.CuckooFeedbackObject")
    @mock.patch("cuckoo.web.controllers.analysis.routes.render_template")
    def test_summary_exception_withanalysis(self, p, q, r, s, client):
        r._get_report.return_value = {
            "info": {
                "id": 1,
            },
        }
        p.side_effect = Exception("fake exception")
        q.return_value.validate.side_effect = CuckooFeedbackError

        with pytest.raises(Exception) as e:
            client.get("/analysis/1/summary/")
        e.match("fake exception")

        q.return_value.add_traceback.assert_called_once()
        q.return_value.include_report_web.assert_called_once()
        q.return_value.include_analysis.assert_called_once()
        s.warning.assert_called_once()
