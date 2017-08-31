# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import flask_testing
import mock
import os
import pytest
import requests
import responses
import tempfile

from cuckoo.common.files import Files
from cuckoo.distributed import api, app, db, instance
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd

def get(rsps, uri, **kwargs):
    rsps.add(responses.GET, "http://localhost" + uri, **kwargs)

def post(rsps, uri, **kwargs):
    rsps.add(responses.POST, "http://localhost" + uri, **kwargs)

@responses.activate
def test_cuckoo_api():
    """Test Distributed Cuckoo's interaction with the Cuckoo API."""
    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        get(rsps, "/machines/list", json={"machines": "foo"})
        assert api.list_machines("http://localhost") == "foo"

        get(rsps, "/cuckoo/status", json={"a": "b"})
        assert api.node_status("http://localhost") == {"a": "b"}

        get(rsps, "/cuckoo/status", body="TIMEOUT", status=500)
        assert api.node_status("http://localhost") is None

        get(rsps, "/cuckoo/status", body=requests.ConnectionError("foo"))
        assert api.node_status("http://localhost") is None

        filepath = tempfile.mktemp()
        open(filepath, "wb").write("hello")

        d = {
            "filename": "bar.exe",
            "path": filepath,
            "package": None,
            "timeout": None,
            "priority": None,
            "options": None,
            "machine": None,
            "platform": None,
            "tags": None,
            "custom": None,
            "owner": None,
            "memory": None,
            "clock": None,
            "enforce_timeout": None,
        }

        post(rsps, "/tasks/create/file", json={"task_id": 12345})
        assert api.submit_task("http://localhost", d) == 12345

        post(rsps, "/tasks/create/file", body=requests.ConnectionError("a"))
        assert api.submit_task("http://localhost", d) is None

        get(rsps, "/tasks/list/100", json={"tasks": ["foo"]})
        assert api.fetch_tasks("http://localhost", "finished", 100) == ["foo"]

        get(rsps, "/tasks/report/1/json", body="A"*1024*1024*8)
        dirpath = tempfile.mkdtemp()
        r = api.store_report("http://localhost", 1, "json", dirpath)
        assert r == (1, "json")
        buf = open(os.path.join(dirpath, "report.json"), "rb").read()
        assert buf == "A"*1024*1024*8

        get(rsps, "/tasks/delete/42")
        assert api.delete_task("http://localhost", 42)

        get(rsps, "/pcap/get/123", body="A"*1024)
        filepath = tempfile.mktemp()
        assert api.fetch_pcap("http://localhost", 123, filepath) is None
        assert open(filepath, "rb").read() == "A"*1024

class TestDatabase(flask_testing.TestCase):
    TESTING = True

    @classmethod
    def setup_class(cls):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        with open(cwd("distributed", "settings.py"), "a+b") as f:
            f.write("SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'\n")
            # TODO Perhaps use tempdir() in settings.py?
            f.write("import tempfile\n")
            f.write("samples_directory = tempfile.gettempdir()\n")
            f.write("reports_directory = tempfile.gettempdir()\n")

    def create_app(self):
        return app.create_app()

    # Unique for these unittests as we're using flask_testing here (rather
    # than the default pytest mechanisms).
    def setUp(self):
        self.db = db.db
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()

    @mock.patch("cuckoo.distributed.instance.node_status")
    @mock.patch("time.sleep")
    def test_scheduler(self, p, q):
        self.db.session.add(db.Node(
            "node0", "http://localhost:8090/", "normal"
        ))
        self.db.session.add(db.Task(path="foobar"))
        self.db.session.commit()

        task = db.Task.query.first()
        assert task.status == db.Task.PENDING

        q.return_value = {
            "tasks": {
                "pending": 0,
            },
        }
        p.side_effect = StopIteration
        with pytest.raises(StopIteration):
            instance.scheduler()

        task = db.Task.query.first()
        assert task.path == "foobar"
        assert task.status == db.Task.ASSIGNED
        assert task.node_id == 1

    def test_task_post(self):
        self.db.session.add(db.Node(
            "node0", "http://localhost:8090/", "normal"
        ))
        self.db.session.commit()

        # No file submitted.
        assert self.client.post("/api/task").status_code == 404

        # Regular submission.
        r = self.client.post("/api/task", data={
            "file": open(__file__, "rb"),
        })
        assert r.status_code == 200
        assert r.json == {
            "success": True,
            "task_id": 1,
        }
        t = db.Task.query.get(1)
        assert t.status == db.Task.PENDING
        assert t.node_id is None

        # Unknown Cuckoo node.
        r = self.client.post("/api/task", data={
            "file": open(__file__, "rb"),
            "node": "notanode",
        })
        assert r.status_code == 404

        # Submit to a node.
        r = self.client.post("/api/task", data={
            "file": open(__file__, "rb"),
            "node": "node0",
        })
        assert r.json == {
            "success": True,
            "task_id": 2,
        }
        t = db.Task.query.get(2)
        assert t.status == db.Task.ASSIGNED
        assert t.node_id == 1

    @mock.patch("cuckoo.distributed.views.api.list_machines")
    def test_node_refresh(self, p):
        node = db.Node("node0", "http://localhost:8090/", "normal")
        self.db.session.add(node)
        m0 = db.Machine("m0", "windows", ["notags"])
        m1 = db.Machine("m1", "windows", ["notags"])
        m2 = db.Machine("m2", "windows", ["notags"])
        self.db.session.add(m0)
        self.db.session.add(m1)
        self.db.session.add(m2)
        node.machines.append(m0)
        node.machines.append(m1)
        node.machines.append(m2)
        self.db.session.commit()

        m0, m1, m2 = db.Machine.query.all()
        assert m0.name == "m0" and m0.tags == ["notags"]
        assert m1.name == "m1" and m1.tags == ["notags"]
        assert m2.name == "m2" and m2.tags == ["notags"]

        p.return_value = [{
            # Existing machine.
            "name": "m0", "platform": "windows", "tags": ["notags"],
        }, {
            # Updated tags.
            "name": "m1", "platform": "windows", "tags": ["sometags"],
        }, {
            # New machine.
            "name": "new0", "platform": "linux", "tags": ["thisistag"],
        }]
        r = self.client.post("/api/node/node0/refresh")
        assert r.status_code == 200
        assert r.json == {
            "success": True, "machines": [{
                "name": "m0", "platform": "windows", "tags": ["notags"],
            }, {
                "name": "m1", "platform": "windows", "tags": ["sometags"],
            }, {
                "name": "new0", "platform": "linux", "tags": ["thisistag"],
            }],
        }

        m0, m1, m2, new0 = db.Machine.query.all()
        assert m0.name == "m0" and m0.node_id == 1
        assert m1.name == "m1" and m1.node_id == 1
        assert m2.name == "m2" and m2.node_id is None
        assert new0.name == "new0" and new0.node_id == 1

        assert m0.platform == "windows" and m0.tags == ["notags"]
        assert m1.platform == "windows" and m1.tags == ["sometags"]
        assert m2.platform == "windows" and m2.tags == ["notags"]
        assert new0.platform == "linux" and new0.tags == ["thisistag"]

    def test_task_delete(self):
        filepath = Files.temp_put("foobar")
        assert os.path.exists(filepath)

        self.db.session.add(db.Task(filepath, status=db.Task.FINISHED))
        assert self.client.delete("/api/task/1").json == {
            "success": True,
        }
        assert not os.path.exists(filepath)
        assert self.client.delete("/api/task/1").json == {
            "success": False,
            "message": "Task already deleted",
        }
        assert not os.path.exists(filepath)
