# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import json
import os.path
import tempfile
import time
import werkzeug

from cuckoo.apps import api
from cuckoo.common.files import Files, temppath
from cuckoo.core.database import Database, TASK_COMPLETED, TASK_RUNNING
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd

db = Database()

class TestAPI(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        db.connect()

        api.app.config["TESTING"] = True
        self.app = api.app.test_client()

    def test_list_tasks(self):
        # Test an empty task list.
        r = json.loads(self.app.get("/tasks/list").data)
        assert r == {"tasks": []}

        # Fill the task list.
        assert self.create_task() == 1
        assert self.create_task() == 2
        assert self.create_task() == 3

        # Test limit option.
        r = json.loads(self.app.get("/tasks/list/1").data)
        assert len(r["tasks"]) == 1
        assert r["tasks"][0]["id"] == 1

        # Offset 1, limit 1.
        r = json.loads(self.app.get("/tasks/list/1/1").data)
        assert len(r["tasks"]) == 1
        assert r["tasks"][0]["id"] == 2

        # Offset 1, limit 2.
        r = json.loads(self.app.get("/tasks/list/2/1").data)
        assert len(r["tasks"]) == 2
        assert r["tasks"][0]["id"] == 2
        assert r["tasks"][1]["id"] == 3

        # List by sample id.
        r = json.loads(self.app.get("/tasks/sample/1").data)
        assert len(r["tasks"]) == 3
        assert sorted((
            r["tasks"][0]["id"], r["tasks"][1]["id"],
            r["tasks"][2]["id"]
        )) == [1, 2, 3]

    def test_list_tasks_unicode(self):
        assert self.create_task(u"\u202e.jpg") == 1
        r = json.loads(self.app.get("/tasks/list").data)
        assert len(r["tasks"]) == 1
        assert r["tasks"][0]["target"].endswith(u"\u202e.jpg")

    def test_create_task(self):
        assert self.create_task() == 1

    def test_create_tasks(self):
        assert self.create_task() == 1
        assert self.create_task() == 2
        assert self.create_task() == 3

        r = json.loads(self.app.get("/tasks/list").data)
        assert len(r["tasks"]) == 3

    def test_create_file_task(self):
        assert self.create_task() == 1
        r = json.loads(self.app.get("/tasks/view/1").data)
        task = r["task"]
        assert task["category"] == "file"
        assert task["sample"]["md5"] == "f2d886558b2866065c3da842bfe13ce6"
        assert open(task["target"], "rb").read() == "eval('alert(1)')"

    def test_create_url_task(self):
        assert self.create_url() == 1
        r = json.loads(self.app.get("/tasks/view/1").data)
        task = r["task"]
        assert task["category"] == "url"
        assert task["target"] == "http://machete.pwn"

    def test_create_submit_multi(self):
        obj = json.loads(self.app.post("/tasks/create/submit", data={
            "files": [
                werkzeug.FileStorage(open("tests/files/pdf0.pdf", "rb")),
                werkzeug.FileStorage(open("tests/files/pdf0.zip", "rb")),
                werkzeug.FileStorage(open("tests/files/pdf0.tgz", "rb")),
            ],
        }).data)
        assert obj["submit_id"] == 1
        assert obj["task_ids"] == [1, 2, 3]

        t1 = db.view_task(1)
        assert t1.category == "file"
        assert t1.target.endswith("pdf0.pdf")
        assert t1.options == {
            "procmemdump": "yes",
        }
        assert os.path.getsize(t1.target) == 680

        t2 = db.view_task(2)
        assert t2.category == "archive"
        assert t2.target.endswith("pdf0.zip")
        assert t2.options == {
            "filename": "files/pdf0.pdf",
            "procmemdump": "yes",
        }

        t3 = db.view_task(3)
        assert t3.category == "archive"
        assert t3.target.endswith("pdf0.zip")
        assert t3.options == {
            "filename": "files/pdf0.pdf",
            "procmemdump": "yes",
        }

    def test_create_submit_opts(self):
        obj = json.loads(self.app.post("/tasks/create/submit", data={
            "files": werkzeug.FileStorage(open("tests/files/pdf0.pdf", "rb")),
            "options": "procmemdump=no,free=yes",
            "memory": True,
            "enforce_timeout": True,
        }).data)
        assert obj["submit_id"] == 1
        assert obj["task_ids"] == [1]
        t = db.view_task(1)
        assert t.memory is True
        assert t.enforce_timeout is True
        assert t.options == {
            "free": "yes",
        }

    def test_create_submit_urls(self):
        obj = json.loads(self.app.post("/tasks/create/submit", data={
            "strings": "\n".join([
                "http://google.com",
                "cuckoosandbox.org",
                "https://1.2.3.4:9001/wow",
            ]),
        }).data)
        assert obj["submit_id"] == 1
        assert obj["task_ids"] == [1, 2, 3]

        t1 = db.view_task(1)
        assert t1.category == "url"
        assert t1.target == "http://google.com"

        t2 = db.view_task(2)
        assert t2.category == "url"
        assert t2.target == "http://cuckoosandbox.org"

        t3 = db.view_task(3)
        assert t3.category == "url"
        assert t3.target == "https://1.2.3.4:9001/wow"

    def test_create_submit_none(self):
        r = self.app.post("/tasks/create/submit")
        assert r.status_code == 500

    def test_delete_task(self):
        task_id = self.create_task()

        r = self.app.get("/tasks/view/%s" % task_id)
        target = json.loads(r.data)["task"]["target"]
        assert os.path.exists(target)

        db.set_status(task_id, TASK_RUNNING)
        r = self.app.get("/tasks/delete/%s" % task_id)
        assert r.status_code == 500

        db.set_status(task_id, TASK_COMPLETED)
        r = self.app.get("/tasks/delete/%s" % task_id)
        assert r.status_code == 200

        r = self.app.get("/tasks/view/%s" % task_id)
        assert r.status_code == 404

        # TODO Should the file be deleted?
        # assert not os.path.exists(target)

    def test_reschedule_task(self):
        task_id = self.create_task()

        # Reschedule the task.
        r = self.app.get("/tasks/reschedule/%s" % task_id)
        data = json.loads(r.data)
        assert data["task_id"] == 2
        assert data["status"] == "OK"
        assert r.status_code == 200

        # Task not found.
        r = self.app.get("/tasks/reschedule/666")
        assert r.status_code == 404

    def test_files_view(self):
        task_id = self.create_task()

        t = json.loads(self.app.get("/tasks/view/%s" % task_id).data)

        # Fetch by sample id.
        r = self.app.get(
            "/files/view/id/%s" % t["task"]["sample_id"]
        )
        assert r.status_code == 200
        sample = json.loads(r.data)
        assert sample["sample"]["id"] == t["task"]["sample_id"]

        # Fetch by md5.
        r = self.app.get("/files/view/md5/f2d886558b2866065c3da842bfe13ce6")
        sample = json.loads(r.data)
        assert sample["sample"]["id"] == 1

        # Fetch by sha256.
        r = self.app.get("/files/view/sha256/c6039bfcdfdfbf714caa94a3bb837a6a4907f3f84ed580ce2916bae7676b68f9")
        sample = json.loads(r.data)
        assert sample["sample"]["id"] == 1

        # Fetch not found id.
        r = self.app.get("/files/view/id/69")
        assert r.status_code == 404

        # Fetch not found md5.
        r = self.app.get("/files/view/md5/zzz886558b2866065c3da842bfe13ce6")
        assert r.status_code == 404

        # Fetch not found sha256.
        r = self.app.get("/files/view/sha256/zzz39bfcdfdfbf714caa94a3bb837a6a4907f3f84ed580ce2916bae7676b68f9")
        assert r.status_code == 404

    def test_files_get(self):
        self.create_task()

        # TODO: add fetch file case.

        # Not found.
        r = self.app.get("/files/get/zzz39bfcdfdfbf714caa94a3bb837a6a4907f3f84ed580ce2916bae7676b68f9")
        assert r.status_code == 404

    def test_completed_after(self):
        a = self.create_task()
        b = self.create_task()

        t1 = int(time.time())
        db.set_status(a, TASK_COMPLETED)

        time.sleep(1)
        t2 = int(time.time())
        db.set_status(b, TASK_COMPLETED)

        r = json.loads(self.app.get("/tasks/list", query_string={
            "completed_after": t1,
        }).data)
        assert len(r["tasks"]) == 2

        r = json.loads(self.app.get("/tasks/list", query_string={
            "completed_after": t2,
        }).data)
        assert len(r["tasks"]) == 1

    def test_list_status(self):
        a = self.create_task()
        b = self.create_task()

        db.set_status(a, TASK_COMPLETED)

        r = json.loads(self.app.get("/tasks/list", query_string={
            "status": TASK_COMPLETED,
        }).data)
        assert len(r["tasks"]) == 1

        db.set_status(a, TASK_COMPLETED)
        r = json.loads(self.app.get("/tasks/list", query_string={
            "status": TASK_COMPLETED,
        }).data)
        assert len(r["tasks"]) == 1

        db.set_status(b, TASK_COMPLETED)
        r = json.loads(self.app.get("/tasks/list", query_string={
            "status": TASK_COMPLETED,
        }).data)
        assert len(r["tasks"]) == 2

    def test_status(self):
        # Create any temporary file, as long as the temporary directory is
        # not empty. Tests bug fix where /cuckoo/status tries to remove the
        # entire temporary directory.
        Files.temp_put("")

        r = self.app.get("/cuckoo/status")
        assert r.status_code == 200

    def test_exit(self):
        assert self.app.get("/exit").status_code == 403

    def test_create_file_abs(self):
        filepath = os.path.join(temppath(), "foobar.txt")
        r = self.app.post("/tasks/create/file", data={
            "file": werkzeug.FileStorage(io.BytesIO("foobar"), filepath),
        })
        t = db.view_task(json.loads(r.data)["task_id"])
        assert open(t.target, "rb").read() == "foobar"
        assert t.target != filepath
        assert t.target.endswith("foobar.txt")

    def test_create_submit_abs(self):
        filepath = os.path.join(temppath(), "foobar.bat")
        r = self.app.post("/tasks/create/submit", data={
            "file": werkzeug.FileStorage(io.BytesIO("foobar"), filepath),
        })
        task_ids = json.loads(r.data)["task_ids"]
        assert len(task_ids) == 1
        t = db.view_task(task_ids[0])
        assert open(t.target, "rb").read() == "foobar"
        assert t.target != filepath
        assert t.target.endswith("foobar.bat")

    def create_task(self, filename="a.js", content="eval('alert(1)')"):
        r = self.app.post("/tasks/create/file", data={
            "file": werkzeug.FileStorage(io.BytesIO(content), filename),
        })
        return json.loads(r.data)["task_id"]

    def create_url(self, url="http://machete.pwn"):
        r = self.app.post("/tasks/create/url", data={
            "url": url,
        })
        return json.loads(r.data)["task_id"]
