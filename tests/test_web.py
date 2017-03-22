# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import io
import json
import mock
import os
import pytest
import responses
import tempfile
import zipfile

from cuckoo.common.exceptions import CuckooFeedbackError
from cuckoo.common.mongo import mongo
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
                "enable-services": False,
                "enforce-timeout": False,
                "full-memory-dump": False,
                "enable-injection": True,
                "process-memory-dump": True,
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
        assert obj["files"][0]["filename"] == "google.com"
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

        submit_id = Database().add_submit(None, None, None)
        r = client.get("/submit/post/1")
        assert r.status_code == 500
        assert "not associated with any tasks" in r.content

        Database().add_path(__file__, submit_id=submit_id)
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

    def test_submit_reboot(self, client):
        t0 = Database().add_path(__file__)
        r = client.get("/analysis/%s/reboot/" % t0)
        assert r.status_code == 302
        t1, = Database().view_submit(1, tasks=True).tasks
        assert Database().view_task(t1.id).custom == "%d" % t0

    def test_resubmit_file(self, client):
        Database().add_path(__file__, options={
            "human": 0, "free": "yes",
        })
        assert client.get("/submit/re/1/").status_code == 302
        submit = Database().view_submit(1)
        assert submit.data["options"] == {
            "enable-injection": False, "simulated-human-interaction": False,
        }

    def test_resubmit_url(self, client):
        Database().add_url("http://bing.com/", options={
            "human": 0, "free": "yes",
        })
        assert client.get("/submit/re/1/").status_code == 302
        submit = Database().view_submit(1)
        assert submit.data["options"] == {
            "enable-injection": False, "simulated-human-interaction": False,
        }

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

        submit = Database().view_submit(1, tasks=True)
        assert len(submit.tasks) == 1
        task = submit.tasks[0]
        assert task.id == 1
        assert task.route == "none"
        assert task.package == "pdf"
        assert os.path.basename(task.target) == "CVE-2011-0611.pdf_"
        assert task.category == "file"
        assert task.priority == 374289732472983
        assert task.custom == ""

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

        # TODO REMOVE THIS BEFORE COMMITTING.
        mongo.db.command("dropDatabase")
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
                else:
                    d["target"] = {
                        "category": "file",
                        "file": {
                            "name": target,
                            "md5": md5,
                        },
                    }
                mongo.db.analysis.save(d)

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
            assert len(obj["tasks"]) == 5
            assert obj["tasks"][0]["id"] == 5
            assert obj["tasks"][0]["target"] == "bar.xls"
            assert obj["tasks"][4]["id"] == 1
            assert obj["tasks"][4]["target"] == "target.exe"

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
