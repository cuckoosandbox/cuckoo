# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import gridfs
import hashlib
import io
import itertools
import json
import mock
import os
import pymongo
import pytest
import responses
import socket
import tempfile
import zipfile

from cuckoo.common.exceptions import CuckooFeedbackError, CuckooCriticalError
from cuckoo.common.files import temppath, Files, Folders
from cuckoo.common.mongo import mongo
from cuckoo.core.database import Database
from cuckoo.core.feedback import CuckooFeedback
from cuckoo.core.submit import SubmitManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd
from cuckoo.processing.static import Static
from cuckoo.web.controllers.analysis.routes import AnalysisRoutes
from cuckoo.web.controllers.submission.api import defaults
from cuckoo.web.utils import render_template

db = Database()

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
        db.connect()

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

    def test_index(self, client):
        assert client.get("/").status_code == 200

    def test_index_post(self, client):
        assert client.post("/").status_code == 405

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"

        d.return_value = task

        assert client.get("/analysis/1/control/").status_code == 200
        assert client.get("/analysis/1/control/tunnel/").status_code == 400

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player_notask(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        d.return_value = None

        assert client.get("/analysis/1/control/").status_code == 404
        assert client.get("/analysis/1/control/tunnel/").status_code == 404

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player_control_disabled(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": False,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"

        d.return_value = task

        assert client.get("/analysis/1/control/").status_code == 404
        assert client.get("/analsys/1/control/tunnel/").status_code == 404

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player_nocontrol_task(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {}
            status = "running"

        d.return_value = task

        assert client.get("/analysis/1/control/").status_code == 404
        assert client.get("/analysis/1/control/tunnel/").status_code == 500

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player_notrunning_task(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "finished"

        d.return_value = task

        assert client.get("/analysis/1/control/").status_code == 404
        assert client.get("/analysis/1/control/tunnel/").status_code == 500

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_player_reported_task(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "reported"

        d.return_value = task

        r = client.get("/analysis/1/control/")
        assert r.status_code == 302
        assert r.url == "http://testserver/analysis/1/summary"

    @pytest.mark.skipif("sys.platform != 'linux2'")
    @mock.patch("threading._Event.is_set")
    @mock.patch("cuckoo.core.database.Database.view_machine_by_label")
    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_tunnel(self, d, d1, l, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"
            guest = mock.MagicMock()

        class machine(object):
            id = 1
            rcparams = {
                "protocol": "rdp",
               "host": "127.0.0.1",
               "port": "3389",
            }

        d.return_value = task
        d1.return_value = machine

        key = client.post("/analysis/1/control/tunnel/?connect").content
        assert len(key) == 36

        # read with read lock set for full coverage
        l.return_value = True
        readreq = client.get("/analysis/1/control/tunnel/?read:%s:0" % key)
        assert readreq.status_code == 200
        assert len(readreq.streaming_content.next()) > 0
        # second read with read lock will be end marker
        assert readreq.streaming_content.next() == "0.;"

        # read without read lock for normal reading
        l.return_value = False
        readreq2 = client.get("/analysis/1/control/tunnel/?read:%s:0" % key)
        assert readreq2.status_code == 200
        # read a few times for coverage of empty reply
        for chunk in itertools.islice(readreq2.streaming_content, 15):
            assert len(chunk) > 0

        assert client.post(
            "/analysis/1/control/tunnel/?write:%s" % key
        ).status_code == 200

    @pytest.mark.skipif("sys.platform != 'linux2'")
    @mock.patch("cuckoo.core.database.Database.view_machine_by_label")
    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_tunnel_connfail(self, d, d1, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                    "guacd_host": "127.0.0.1",
                    "guacd_port": 9999,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"
            guest = mock.MagicMock()

        class machine(object):
            id = 1
            rcparams = {
                "protocol": "rdp",
                "host": "127.0.0.1",
                "port": "3389",
            }

        d.return_value = task
        d1.return_value = machine

        r = client.post(
            "/analysis/1/control/tunnel/?connect"
        )
        assert r.status_code == 500
        assert json.loads(r.content) == {
            "status": "failed",
            "message": "connection failed",
        }

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_tunnel_control_disabled(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": False,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"
            guest = mock.MagicMock()

        d.return_value = task
        assert client.get("/analysis/1/control/tunnel/").status_code == 500

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_tunnel_invalid(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"
            guest = mock.MagicMock()

        d.return_value = task
        assert client.get("/analysis/1/control/tunnel/?X:Y").status_code == 400

    @mock.patch("cuckoo.core.database.Database.view_task")
    def test_rdp_tunnel_noguest(self, d, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "remotecontrol": {
                    "enabled": True,
                },
            },
        })

        class task(object):
            id = 1
            options = {
                "remotecontrol": "yes",
            }
            status = "running"
            guest = None

        d.return_value = task
        r = client.get("/analysis/1/control/tunnel/?connect")
        assert r.status_code == 500
        assert json.loads(r.content) == {
            "status": "failed",
            "message": "task is not assigned to a machine yet",
        }

    def test_rdp_report(self, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "mongodb": {
                    "enabled": True,
                },
            },
        })

        assert client.post(
            "/analysis/1/control/screenshots/",
            json.dumps(["list"]),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        ).status_code == 501

    @mock.patch("cuckoo.web.controllers.analysis.control.api.ControlApi.get_report")
    def test_rdp_screenshots(self, c, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "mongodb": {
                    "enabled": True,
                },
            },
        })

        c.side_effect = lambda x: {
            "shots": [],
        } if x == 1 else {}

        Folders.create(cwd("shots", analysis=1))

        def do_req(task_id, data):
            return client.post(
                "/analysis/%d/control/screenshots/" % int(task_id),
                json.dumps(data),
                "application/json",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest"
            )

        valid_scr = {"id": 0, "data": "data:image/png;base64,iVBORw=="}

        # valid screenshot
        r = do_req(1, [valid_scr])
        assert r.status_code == 200

        # no data
        r = do_req(1, None)
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "screenshots missing",
        }

        # invalid task
        r = do_req(2, [valid_scr])
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "report missing",
        }

        # missing field
        r = do_req(1, [
            {"id": 0},
        ])
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "invalid format",
        }

        # no comma
        r = do_req(1, [
            {"id": 0, "data": "partial"},
        ])
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "invalid format",
        }

        # illegal type
        r = do_req(1, [
            {"id": 0, "data": "illegal, AAAA"},
        ])
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "invalid format",
        }

        # no PNG magic
        r = do_req(1, [
            {"id": 0, "data": "data:image/png;base64,Tk9QRQ=="}
        ])
        assert r.status_code == 501
        assert json.loads(r.content) == {
            "status": False,
            "message": "invalid format",
        }

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
            "id": 1,
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

    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    def test_summary_pdf_metadata(self, p, request):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "pdf",
            "target": "pdf-sample.pdf",
        })
        s.set_options({
            "pdf_timeout": 10,
        })
        s.file_path = "tests/files/pdf-sample.pdf"

        p._get_report.return_value = {
            "static": s.run(),
        }
        r = AnalysisRoutes.detail(request, 1, "static").content
        assert "Microsoft Word 8.0" in r
        assert "This is a test PDF file" in r

    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    def test_summary_pdf_nometadata(self, p, request):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "pdf",
            "target": __file__,
        })
        s.set_options({
            "pdf_timeout": 10,
        })
        s.file_path = __file__

        p._get_report.return_value = {
            "static": s.run(),
        }
        r = AnalysisRoutes.detail(request, 1, "static").content
        assert "No PDF metadata could be extracted!" in r

    def test_submit_defaults(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "routing": {
                "routing": {
                    "route": "internet",
                    "drop": True,
                    "internet": "eth0",
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
                "drop": True,
                "internet": True,
                "inetsim": True,
                "tor": True,
                "vpns": [
                    "france", "italy",
                ],
            },
            "options": {
                "enforce-timeout": False,
                "full-memory-dump": False,
                "enable-injection": True,
                "process-memory-dump": True,
                "remote-control": False,
                "simulated-human-interaction": True,
            }
        }
        buf = open(cwd("conf", "routing.conf")).read()
        assert "[italy]" in buf
        assert "[france]" in buf
        assert "vpns = france, italy" in buf

    def test_submit_routing_defaults(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        obj = defaults()
        assert obj["routing"] == {
            "route": "none",
            "drop": False,
            "internet": False,
            "inetsim": False,
            "tor": False,
            "vpns": [],
        }

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
        assert obj["files"][0]["filename"] == "http://google.com"
        assert obj["defaults"]["priority"] == 2
        assert obj["defaults"]["options"]["process-memory-dump"] is True

    def test_submission_submit(self, client):
        r = client.get("/submit/")
        assert r.status_code == 200
        assert r.templates[0].name == "submission/submit.html"

    def test_submission_postsubmit(self, client):
        r = client.get("/submit/post/1")
        assert r.status_code == 500
        assert "Invalid Submit ID" in r.content

        submit_id = db.add_submit(None, None, None)
        r = client.get("/submit/post/1")
        assert r.status_code == 500
        assert "not associated with any tasks" in r.content

        db.add_path(__file__, submit_id=submit_id)
        r = client.get("/submit/post/1")
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

        r, _, _ = SubmitManager().get_files(1)
        assert len(r) == 1
        assert r[0].filesize == os.path.getsize(__file__)

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
                "include_analysis": False,
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 501

        obj = json.loads(r.content)
        assert obj["status"] is False
        assert "Invalid email" in obj["message"]

    # TODO Re-enable this unit test if this API endpoint is enabled.
    def _test_api_post_task_info_simple(self, client):
        db.add_path("tests/files/pdf0.pdf")
        r = client.post(
            "/analysis/api/task/info/",
            json.dumps({
                "task_id": 1,
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200
        obj = json.loads(r.content)
        assert obj["data"]["task"]["target"] == "pdf0.pdf"

    def test_api_post_not_json(self, client):
        r = client.post(
            "/analysis/api/tasks/info/",
            "NOTJSON",
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 501
        assert "not JSON" in r.content

    def test_api_post_tasks_info_simple(self, client):
        db.add_path(__file__)
        db.add_url("http://cuckoosandbox.org")
        db.add_archive("tests/files/pdf0.zip", "pdf0.pdf", "pdf")
        r = client.post(
            "/analysis/api/tasks/info/",
            json.dumps({
                "task_ids": [1, 2, 3],
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200
        obj = json.loads(r.content)
        assert obj["data"]["1"]["category"] == "file"
        assert obj["data"]["1"]["target"] == "test_web.py"
        assert obj["data"]["2"]["category"] == "url"
        assert obj["data"]["2"]["target"] == "hxxp://cuckoosandbox.org"
        assert obj["data"]["3"]["category"] == "archive"
        assert obj["data"]["3"]["options"]["filename"] == "pdf0.pdf"
        assert obj["data"]["3"]["target"] == "pdf0.pdf @ pdf0.zip"

    @mock.patch("cuckoo.web.controllers.analysis.api.db")
    @mock.patch("cuckoo.web.controllers.analysis.analysis.db")
    def test_api_post_tasks_info_many(self, p, q, client):
        class task(object):
            id = 0
            guest = None
            errors = []
            sample_id = None

            @classmethod
            def to_dict(cls):
                cls.id += 1
                return {
                    "id": cls.id,
                    "category": "file",
                    "target": "/tmp/hello",
                }

        p.view_tasks.return_value = [task] * 100
        r = client.post(
            "/analysis/api/tasks/info/",
            json.dumps({
                "task_ids": range(100),
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200
        p.view_task.assert_not_called()
        q.view_task.assert_not_called()
        q.view_tasks.assert_called_once()

    def test_api_post_tasks_info_str(self, client):
        r = client.post(
            "/analysis/api/tasks/info/",
            json.dumps({
                "task_ids": ["1"],
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 501

    def test_view_error_has_envvar(self, client, settings):
        """Ensure that render_template() is used in view_error()."""
        settings.DEBUG = True
        r = client.get("/analysis/search/")
        assert r.status_code == 500

    @pytest.mark.skipif("sys.platform != 'linux2'")
    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    def test_export_infoleak(self, p, client):
        p._get_report.return_value = {
            "info": {
                "analysis_path": "/tmp",
            },
        }
        r = client.post(
            "/analysis/api/task/export_estimate_size/",
            json.dumps({
                "task_id": 1,
                "dirs": [],
                "files": [
                    # TODO Should we support individual files in analysis
                    # directories, e.g., "shots/0001.png"?
                    "../../../../../../etc/passwd",
                ],
            }),
            "application/json",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        assert r.status_code == 200
        # The file should not be found and as such have size zero.
        assert not json.loads(r.content)["size"]

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
        db.connect()

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

    def test_submit_reboot(self, client):
        t0 = db.add_path(__file__)
        r = client.get("/analysis/%s/reboot/" % t0)
        assert r.status_code == 302
        t1, = db.view_submit(1, tasks=True).tasks
        assert db.view_task(t1.id).custom == "%d" % t0

    def test_resubmit_file(self, client):
        db.add_path(__file__, options={
            "human": 0, "free": "yes",
        })
        assert client.get("/submit/re/1/").status_code == 302
        submit = db.view_submit(1)
        assert submit.data["options"] == {
            "enable-injection": False,
            "simulated-human-interaction": False,
        }

    def test_resubmit_url(self, client):
        db.add_url("http://bing.com/", options={
            "human": 0, "free": "yes",
        })
        assert client.get("/submit/re/1/").status_code == 302
        submit = db.view_submit(1)
        assert submit.data["options"] == {
            "enable-injection": False,
            "simulated-human-interaction": False,
        }

    def test_resubmit_file_missing(self, client):
        filepath = Files.temp_put("hello world")
        db.add_path(filepath, options={
            "human": 0, "free": "yes",
        })
        os.unlink(filepath)
        assert client.get("/submit/re/1/").status_code == 500

    def test_import_analysis(self, client):
        # Pack sample_analysis_storage into an importable .zip analysis.
        buf = io.BytesIO()
        z = zipfile.ZipFile(buf, "w")
        l = os.walk("tests/files/sample_analysis_storage")
        for dirpath, dirnames, filenames in l:
            for filename in filenames:
                if os.path.basename(dirpath) == "sample_analysis_storage":
                    relapath = filename
                else:
                    relapath = "%s/%s" % (os.path.basename(dirpath), filename)
                z.write(os.path.join(dirpath, filename), relapath)
        z.close()

        buf.seek(0)
        r = client.post("/analysis/import/", {
            "analyses": buf,
        })
        assert r.status_code == 302

        submit = db.view_submit(1, tasks=True)
        assert len(submit.tasks) == 1
        task = submit.tasks[0]
        assert task.id == 1
        assert task.route == "none"
        assert task.package == "pdf"
        assert os.path.basename(task.target) == "CVE-2011-0611.pdf_"
        assert task.category == "file"
        assert task.priority == 374289732472983
        assert task.custom == ""

        buf.seek(0)
        r = client.post("/analysis/import/", {
            "analyses[]": buf,
        })
        assert r.status_code == 302
        submit = db.view_submit(2, tasks=True)
        assert len(submit.tasks) == 1

    def test_import_analysis_exc(self, client):
        @mock.patch("cuckoo.web.controllers.submission.routes.log")
        def get_error(buf, p):
            r = client.post("/analysis/import/", {
                "analyses": io.BytesIO(buf),
            })
            assert r.status_code == 302
            p.warning.assert_called_once()
            return p.warning.call_args[0][2].message

        def get_error2(kw):
            buf = io.BytesIO()
            z = zipfile.ZipFile(buf, "w")
            for key, value in kw.items():
                z.writestr(key, value)
            z.close()
            return get_error(buf.getvalue())

        assert "is not a proper" in get_error("NOTAZIP")

        assert "potentially incorrect" in get_error2({
            "/etc/passwd": "notyourpasswd",
        })
        assert "potentially incorrect" in get_error2({
            "reports/../../../etc/passwd": "notyourpassword",
        })

        assert "task.json file is required" in get_error2({})

        assert "provided task.json file" in get_error2({
            "task.json": "NOTAJSON",
        })
        assert "provided task.json file" in get_error2({
            "task.json": json.dumps({
                "options": {},
            }),
        })

def test_mongodb_disabled():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": False,
            },
        },
    })
    with pytest.raises(SystemExit) as e:
        import cuckoo.web.web.settings
        cuckoo.web.web.settings.red("...")  # Fake usage.
    e.match("to have MongoDB up-and-running")

@mock.patch("cuckoo.common.mongo.log")
@mock.patch("cuckoo.common.mongo.socket.create_connection")
@mock.patch("cuckoo.common.mongo.gridfs")
@mock.patch("cuckoo.common.mongo.pymongo.MongoClient")
def test_mongodb_offline(p, q, r, s):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "reporting": {
            "mongodb": {
                "enabled": True,
            },
        },
    })

    r.side_effect = socket.error("error")
    db = p.return_value.__getitem__.return_value
    db.collection_names.side_effect = pymongo.errors.PyMongoError("error")

    with pytest.raises(CuckooCriticalError) as e:
        mongo.init()
        mongo.connect()
    e.match("Unable to connect to MongoDB")
    s.warning.assert_called_once()

@pytest.mark.skipif("sys.platform != 'linux2'")
class TestMongoInteraction(object):
    @classmethod
    def setup_class(cls):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "mongodb": {
                    "enabled": True,
                    "db": "cuckootest",
                },
            },
        })
        mongo.init()
        mongo.connect()

    class TestTasksRecent(object):
        @classmethod
        def setup_class(cls):
            tasks = [
                (1, "file", "exe", "target.exe", 8, "thisisamd5"),
                (2, "url", "ie", "http://google.com/", 2, None),
                (3, "file", "doc", "malicious.doc", 11, "anothermd5"),
                (4, "file", "vbs", "foo.vbs", 0, "didnothing"),
                (5, "file", "xls", "bar.xls", 7, "verymalicious"),
                (6, "archive", "pdf", "pdf0.zip", 3, "amd5"),
            ]

            for id_, category, package, target, score, md5 in tasks:
                d = {
                    "info": {
                        "id": id_,
                        "category": category,
                        "package": package,
                        "score": score,
                    },
                }
                if category == "url":
                    d["target"] = {
                        "category": "url",
                        "url": target,
                    }
                elif category == "archive":
                    d["target"] = {
                        "category": "archive",
                        "archive": {},
                        "filename": "pdf0.pdf",
                        "human": "pdf0.pdf @ pdf0.zip",
                    }
                else:
                    d["target"] = {
                        "category": "file",
                        "file": {
                            "name": target,
                            "md5": md5,
                        },
                    }
                mongo.db.analysis.save(d)

            # Handle analyses that somehow don't have a "target" field.
            mongo.db.analysis.save({
                "info": {
                    "id": 999,
                    "category": "archive",
                },
            })

        def req(self, client, **kw):
            return client.post(
                "/analysis/api/tasks/recent/",
                json.dumps(kw),
                "application/json",
                HTTP_X_REQUESTED_WITH="XMLHttpRequest"
            )

        def test_normal(self, client):
            r = self.req(client)
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 7
            assert obj["tasks"][1]["id"] == 6
            assert obj["tasks"][1]["target"] == "pdf0.pdf @ pdf0.zip"
            assert obj["tasks"][6]["id"] == 1
            assert obj["tasks"][6]["target"] == "target.exe"

        def test_limit2(self, client):
            r = self.req(client, limit=2)
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 2

        def test_score_5_10(self, client):
            r = self.req(client, score="5-10")
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 3
            assert obj["tasks"][0]["id"] == 5
            assert obj["tasks"][1]["id"] == 3
            assert obj["tasks"][2]["id"] == 1

        def test_file_category(self, client):
            r = self.req(client, cats=["file"])
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 4

        def test_archive_category(self, client):
            r = self.req(client, cats=["archive"])
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 2

        def test_doc_packages(self, client):
            r = self.req(client, packs=["doc", "vbs", "xls", "js"])
            assert r.status_code == 200
            obj = json.loads(r.content)
            assert len(obj["tasks"]) == 3

        def test_invld_limit(self, client):
            r = self.req(client, limit="notanint")
            assert r.status_code == 501
            assert "invalid limit" in r.content

        def test_invld_offset(self, client):
            r = self.req(client, offset="notanint")
            assert r.status_code == 501
            assert "invalid offset" in r.content

        def test_invld_score(self, client):
            assert self.req(client, score="!!").status_code == 501
            assert self.req(client, score="1-11").status_code == 501
            assert self.req(client, score="11-9").status_code == 501
            assert self.req(client, score="1--3").status_code == 501
            assert self.req(client, score="1-a").status_code == 501

        def test_invld_categories(self, client):
            assert self.req(client, cats="file").status_code == 501
            assert self.req(client, cats=["file", 1]).status_code == 501
            assert self.req(client, cats=["file"]).status_code == 200

        def test_invld_packages(self, client):
            assert self.req(client, packs="exe").status_code == 501
            assert self.req(client, packs=["doc", 1]).status_code == 501
            assert self.req(client, packs=["xls", "doc"]).status_code == 200

    class TestFile(object):
        def test_empty(self, client):
            r = client.get("/file/screenshots//")
            assert r.status_code == 500

            r = client.get("/file/screenshots//nofetch/")
            assert r.status_code == 500

        def test_invalid(self, client):
            with pytest.raises(pymongo.errors.InvalidId):
                client.get("/file/screenshots/hello/")

        def test_404(self, client):
            with pytest.raises(gridfs.errors.NoFile):
                client.get("/file/screenshots/%s/" % ("A"*24))

        def test_has_file(self, client):
            data = os.urandom(32)

            obj = mongo.grid.new_file(
                filename="dump.pcap",
                contentType="application/vnd.tcpdump.pcap",
                sha256=hashlib.sha256(data).hexdigest()
            )
            obj.write(data)
            obj.close()

            r = client.get("/file/something/%s/nofetch/" % obj._id)
            assert r.status_code == 200
            assert r.content == data

class TestApiEndpoints(object):
    @mock.patch("os.unlink")
    def test_status(self, p, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "moloch": {
                    "enabled": True,
                },
            },
        })
        db.connect()
        r = client.get("/cuckoo/api/status/")
        assert r.status_code == 200
        assert p.call_args_list[0][0][0].startswith(temppath())

    def test_api_status200(self, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        Database().connect()
        r = client.get("/cuckoo/api/status")
        assert r.status_code == 200

    @mock.patch("cuckoo.web.controllers.cuckoo.api.check_version")
    def test_api_fetch_once(self, p, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        Database().connect()

        p.return_value = {
            "version": "2.0.5",
            "blogposts": [{
                "title": "title",
                "important": False,
                "oneline": "this is oneliner",
                "url": "https://cuckoosandbox.org/blog/blogpost",
                "date": "today or tomorrow",
            }],
        }

        # Clear the 'updates' variable.
        from cuckoo.web.controllers.cuckoo.api import updates
        updates.clear()

        r = client.get("/cuckoo/api/status")
        assert r.status_code == 200
        r = client.get("/cuckoo/api/status")
        assert r.status_code == 200
        r = json.loads(r.content)["data"]
        assert r["latest_version"] == "2.0.5"
        assert r["blogposts"] == [mock.ANY]

        p.assert_called_once()

    @mock.patch("multiprocessing.cpu_count")
    def _test_api_status_cpucount(self, p, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        Database().connect()
        p.return_value = 2
        r = client.get("/cuckoo/api/status")
        assert r.status_code == 200
        assert json.loads(r.content)["cpucount"] == 2

    @mock.patch("cuckoo.web.controllers.cuckoo.api.rooter")
    def test_api_vpnstatus(self, p, client):
        p.return_value = []
        r = client.get("/cuckoo/api/vpn/status")
        assert r.status_code == 200

    @mock.patch("cuckoo.web.controllers.analysis.routes.AnalysisController")
    def test_analysis_summary(self, p, client):
        p.get_report.side_effect = Exception
        with pytest.raises(Exception):
            client.get("/analysis/1/summary")

class TestMoloch(object):
    def test_disabled(self, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "moloch": {
                    "enabled": False,
                    "host": "molochhost",
                },
            },
        })
        assert client.get("/analysis/moloch/1.2.3.4//////").status_code == 500

    def test_host(self, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "moloch": {
                    "enabled": True,
                    "host": "molochhost",
                },
            },
        })
        r = client.get("/analysis/moloch//google.com/////")
        assert r.status_code == 302
        assert "https://molochhost" in r["Location"]

    def test_insecure(self, client):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "reporting": {
                "moloch": {
                    "enabled": True,
                    "host": "molochhost",
                    "insecure": True,
                },
            },
        })
        r = client.get("/analysis/moloch//////12345/")
        assert r.status_code == 302
        assert "http://molochhost" in r["Location"]

class TestTemplates(object):
    def test_pdf_no_metadata(self, request):
        r = render_template(request, "analysis/pages/static/index.html", report={
            "analysis": {
                "static": {
                    "pdf": [{
                        "creation": "",
                        "modification": "",
                        "version": 1,
                        "urls": [],
                    }],
                },
            },
        }, page="static")
        assert "No PDF metadata" in r.content

    def test_pdf_only_1_url(self, request):
        r = render_template(request, "analysis/pages/static/index.html", report={
            "analysis": {
                "static": {
                    "pdf": [{
                        "creation": "",
                        "modification": "",
                        "version": 1,
                        "urls": [
                            "http://thisisaurl.com/hello",
                        ],
                    }],
                },
            },
        }, page="static")
        assert "No PDF metadata" not in r.content
        assert ">http://thisisaurl.com/hello</li>" in r.content

    def test_pdf_2_version_with_url(self, request):
        r = render_template(request, "analysis/pages/static/index.html", report={
            "analysis": {
                "static": {
                    "pdf": [{
                        "version": 1,
                        "urls": [
                            "http://thisisaurl.com/url1",
                        ],
                    }, {
                        "version": 2,
                        "urls": [
                            "http://thisisaurl.com/url2",
                        ],
                    }],
                },
            },
        }, page="static")
        assert "No PDF metadata" not in r.content
        assert ">http://thisisaurl.com/url1</li>" in r.content
        assert ">http://thisisaurl.com/url2</li>" in r.content
        ul1 = r.content.index('<ul class="list-group">')
        url1 = r.content.index("url1")
        url2 = r.content.index("url2")
        ul2 = r.content.index("</ul>", ul1)
        assert url1 >= ul1 and url1 < ul2
        assert url2 >= ul1 and url2 < ul2

    def test_pdf_has_javascript(self, request):
        r = render_template(request, "analysis/pages/static/index.html", report={
            "analysis": {
                "static": {
                    "pdf": [{
                        "creation": "",
                        "modification": "",
                        "version": 1,
                        "urls": [],
                        "javascript": [{
                            "orig_code": "alert(1)",
                            "beautified": "alert(2)",
                        }],
                    }],
                },
            },
        }, page="static")
        assert "No PDF metadata" not in r.content
        assert '<code class="javascript">alert(1)</code>' in r.content
        assert '<code class="javascript">alert(2)</code>' in r.content

    def test_network_no_pcap(self, request):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        r = render_template(request, "analysis/pages/network/index.html", report={
            "analysis": {
                "network": {
                    "pcap_id": None,
                },
            },
        })
        assert "No PCAP file was identified" in r.content

    def test_network_has_pcap(self, request):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        r = render_template(request, "analysis/pages/network/index.html", report={
            "analysis": {
                "network": {
                    "pcap_id": "wehaveapcapwinner",
                    "hosts": [], "dns": [], "tcp": [], "udp": [], "icmp": [],
                    "irc": [], "http": [], "http_ex": [],
                },
            },
        })
        assert "Download pcap file" in r.content
        assert "network-analysis-hosts" in r.content
        assert "network-analysis-dns" in r.content

    def test_summary_has_no_cfgextr(self, request):
        r = render_template(request, "analysis/pages/summary/index.html", report={
            "analysis": {
                "info": {
                    "category": "file",
                    "score": 1,
                },
                "metadata": {},
            },
        })
        assert "Malware Configuration" not in r.content

    def test_summary_has_cfgextr(self, request):
        r = render_template(request, "analysis/pages/summary/index.html", report={
            "analysis": {
                "info": {
                    "category": "file",
                    "score": 10,
                },
                "metadata": {
                    "cfgextr": [{
                        "family": "Family",
                        "cnc": [
                            "http://cncurl1",
                            "http://cncurl2",
                        ],
                        "url": [
                            "http://downloadurl1",
                            "http://downloadurl2",
                        ],
                        "type": "thisistype",
                    }],
                },
            },
        })
        assert "Malware Configuration" in r.content
        assert "CnC" in r.content
        assert "URLs" in r.content
        assert "thisistype" in r.content

    def test_summary_has_2_cfgextr(self, request):
        r = render_template(request, "analysis/pages/summary/index.html", report={
            "analysis": {
                "info": {
                    "category": "file",
                    "score": 10,
                },
                "metadata": {
                    "cfgextr": [{
                        "family": "familyA",
                        "cnc": [
                            "http://familyAcnc",
                        ],
                    }, {
                        "family": "familyB",
                        "cnc": [
                            "http://familyBcnc",
                        ],
                    }],
                },
            },
        })
        assert "Malware Configuration" in r.content
        assert "familyA" in r.content
        assert "familyB" in r.content
