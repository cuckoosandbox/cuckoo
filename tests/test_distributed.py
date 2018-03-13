# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import flask_testing
import io
import json
import mock
import os
import pytest
import requests
import responses
import tempfile

from cuckoo.common.files import Files
from cuckoo.distributed import api, app, db, instance
from cuckoo.distributed.misc import StatsCache
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

        get(rsps, ":80/cuckoo/status", json={"a": "b"})
        assert api.node_status("http://localhost:80") == {"a": "b"}

        get(rsps, ":8080/cuckoo/status", body="TIMEOUT", status=500)
        assert api.node_status("http://localhost:8080") is None

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

        post(rsps, ":80/tasks/create/file", json={"task_id": 12345})
        assert api.submit_task("http://localhost:80", d) == 12345

        post(
            rsps, ":8080/tasks/create/file",
            body=requests.ConnectionError("a")
        )
        assert api.submit_task("http://localhost:8080", d) is None

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
        r = self.client.post("/api/task")
        assert r.status_code == 404
        assert r.json == {
            "success": False, "message": "No file has been provided",
        }

        # Empty file submission.
        r = self.client.post("/api/task", data={
            "file": (io.BytesIO(""), "1.filename"),
        })
        assert r.status_code == 404
        assert r.json == {
            "success": False, "message": "Provided file is empty",
        }

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
        assert r.json == {
            "success": False, "message": "Node not found",
        }

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

    def test_tasks_delete(self):
        filepath1 = Files.temp_put("foobar")
        filepath2 = Files.temp_put("foobar")
        assert os.path.exists(filepath1)
        assert os.path.exists(filepath2)

        self.db.session.add(db.Task(filepath1, status=db.Task.FINISHED))
        self.db.session.add(db.Task(filepath2, status=db.Task.FINISHED))
        data = {
            "task_ids": "1 2",
        }
        assert self.client.delete("/api/tasks", data=data).json == {
            "success": True,
        }
        assert not os.path.exists(filepath1)
        assert not os.path.exists(filepath2)
        assert self.client.delete("/api/task/1").json == {
            "success": False,
            "message": "Task already deleted",
        }
        assert self.client.delete("/api/task/2").json == {
            "success": False,
            "message": "Task already deleted",
        }
        assert not os.path.exists(filepath1)
        assert not os.path.exists(filepath2)

class TestAPIStats(flask_testing.TestCase):
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

        # Create some tasks in task with different statuses
        dates_completed = [None, None, None, "2017-8-15 14:00:00"]
        statuses = ["pending", "pending", "pending", "deleted"]
        prios = [1, 1, 5, 1]
        for c in range(4):
            fd, path = tempfile.mkstemp()
            with open(path, "wb") as fw:
                fw.write(os.urandom(64))

            kwargs = {
                "status": statuses[c],
                "priority": prios[c],
            }
            task = db.Task(
                path=path, filename=os.path.basename(path), **kwargs
            )
            if dates_completed[c] is not None:
                task.completed = datetime.datetime.strptime(
                    dates_completed[c], "%Y-%m-%d %H:%M:%S"
                )
            task.submitted = datetime.datetime.strptime(
                "2017-8-15 13:40:00", "%Y-%m-%d %H:%M:%S"
            )
            self.db.session.add(task)
            self.db.session.commit()

        # Create some nodes and status reports
        node_statuses = json.load(open("tests/files/nodestatus.json", "rb"))

        now = datetime.datetime.strptime(
            "2017-8-15 13:40:00", "%Y-%m-%d %H:%M:%S"
        )

        for name in ["node1", "node2"]:
            self.db.session.add(db.Node(
                name, "http://localhost:9085/", "normal"
            ))
        for node_status in node_statuses:
            now = now + datetime.timedelta(seconds=10)
            name = node_status.get("hostname")
            self.db.session.add(db.NodeStatus(name, now, node_status))
            self.db.session.commit()

        self.db.session.flush()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()

    def test_stats(self):
        r = self.client.get("/api/stats/2017-8-16")

        correct_reply = json.load(
            open("tests/files/statsapireply.json", "rb")
        )

        keys = r.json.keys()
        assert r.status_code == 200
        assert r.json == correct_reply
        assert len(keys) == 9

        for node in r.json["nodes"]:
            r = self.client.get(
                "/api/stats?nodes=%s&include=memory_usage" % node
            )
            assert r.status_code == 200
            assert r.json["memory_usage"]["hour"].keys() == [node]

        keys.remove("nodes")
        for stat in keys:
            r = self.client.get(
                "/api/stats/2017-8-16?include=%s" % stat
            )
            assert r.status_code == 200
            assert r.json[stat] == correct_reply[stat]

        r = self.client.get("/api/stats/2017-8-16?period=hour")
        assert "week" not in r.json["vm_running"]
        assert "day" not in r.json["vm_running"]

        r = self.client.get("/api/stats/2017-8-16/13:40")
        assert r.status_code == 200

class TestStatsCache(object):
    def test_update_increment(self):
        sc = StatsCache()
        sc._init_stats()
        dt = datetime.datetime.now()
        key = sc.round_nearest_step(dt, 15).strftime(sc.dt_ftm)
        sc.update(name="test1", step_size=15)

        assert sc.stats["test1"][key] == 1

    def test_update_increment_changed(self):
        sc = StatsCache()
        sc._init_stats()
        dt = datetime.datetime.now()
        key = sc.round_nearest_step(dt, 15).strftime(sc.dt_ftm)
        sc.update(name="test1", step_size=15)
        sc.update(name="test1", step_size=15, increment_by=1337)

        assert sc.stats["test1"][key] == 1338

    def test_update_set_dt_value(self):
        sc = StatsCache()
        sc._init_stats()
        value = os.urandom(64)
        dt1 = datetime.datetime(2017, 5, 15, 15, 9, 22)
        sc.update(name="test2", step_size=15, set_dt=dt1, set_value=value)
        dt2 = datetime.datetime(2017, 5, 15, 15, 13, 42)

        assert sc.get_stat(name="test2", dt=dt2, step_size=15) == value

    def test_update_key_prefix(self):
        sc = StatsCache()
        sc._init_stats()
        value = os.urandom(64)
        dt1 = datetime.datetime(2017, 5, 15, 15, 9, 22)
        dt2 = datetime.datetime(2017, 5, 15, 15, 11, 42)
        sc.update(
            name="test3", step_size=15, set_dt=dt1,
            set_value=value, key_prefix="node1"
        )

        key = "node1%s" % sc.round_nearest_step(dt1, 15).strftime(sc.dt_ftm)
        assert sc.get_stat("test3", dt2, 15, key_prefix="node1") == value
        assert sc.stats["test3"][key] == value

    def test_get_now_is_none(self):
        sc = StatsCache()
        sc._init_stats()
        value = os.urandom(64)
        sc.update(
            name="test4", step_size=15, set_value=value,
            set_dt=datetime.datetime.now()
        )

        assert sc.get_stat(
            name="test4", step_size=15, dt=datetime.datetime.now()
        ) is None

    def test_get_nonexistant(self):
        sc = StatsCache()
        sc._init_stats()
        dt = datetime.datetime(2017, 5, 15, 15, 9, 22)

        assert sc.get_stat(name="test5", dt=dt, step_size=15) is None
        sc.update(
            name="test5", step_size=15,
            set_dt=datetime.datetime(2017, 5, 15, 1, 5, 19)
        )
        assert sc.get_stat(name="test5", dt=dt, step_size=15) is None

    def test_update_to_default(self):
        sc = StatsCache()
        sc._init_stats()
        dt = datetime.datetime(2017, 5, 15, 15, 9, 22)

        sc.update(name="test8", set_dt=dt, step_size=15)
        assert sc.get_stat(name="test8", dt=dt, step_size=15) == {}

    def test_update_changed_default(self):
        sc = StatsCache()
        sc._init_stats()
        dt = datetime.datetime(2017, 5, 15, 15, 9, 22)

        sc.update(name="test9", set_dt=dt, step_size=15, default="Doge")
        assert sc.get_stat(name="test9", dt=dt, step_size=15) == "Doge"

    def test_round_nearest_step(self):
        now = datetime.datetime(2017, 5, 15, 15, 11, 22)
        five_min = datetime.datetime(2017, 5, 15, 15, 15)
        ten_min = datetime.datetime(2017, 5, 15, 15, 20)
        fifteen_min = datetime.datetime(2017, 5, 15, 15, 15)
        thirty_min = datetime.datetime(2017, 5, 15, 15, 30)
        sixty_min = datetime.datetime(2017, 5, 15, 16)

        sc = StatsCache()
        assert sc.round_nearest_step(now, 5) == five_min
        assert sc.round_nearest_step(now, 10) == ten_min
        assert sc.round_nearest_step(now, 15) == fifteen_min
        assert sc.round_nearest_step(now, 30) == thirty_min
        assert sc.round_nearest_step(now, 60) == sixty_min

    def test_constants(self):
        sc = StatsCache()
        assert sc.dt_ftm == "%Y-%m-%d %H:%M:%S"
        assert sc.max_cache_days == 60

    def test_reset(self):
        sc = StatsCache()
        assert len(sc.stats) > 1
        sc._reset_at = datetime.datetime.now() - datetime.timedelta(days=1)
        sc.get_stat(name="test7", dt=datetime.datetime.now(), step_size=15)
        assert len(sc.stats) == 1
