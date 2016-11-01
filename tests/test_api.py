# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import json
import os.path
import shutil
import tempfile
import time
import werkzeug

from cuckoo.apps import api
from cuckoo.common.files import Folders, Files
from cuckoo.core.database import Database, TASK_COMPLETED, TASK_RUNNING
from cuckoo.misc import set_cwd

CUCKOO_CONF = """
[cuckoo]
tmppath = /tmp
"""

class TestAPI(object):
    def setup(self):
        self.dirpath = tempfile.mkdtemp()
        set_cwd(self.dirpath)
        Database().connect()

        api.app.config["TESTING"] = True
        self.app = api.app.test_client()

        Folders.create(self.dirpath, "conf")
        Files.create(self.dirpath, "conf/cuckoo.conf", CUCKOO_CONF)

    def teardown(self):
        shutil.rmtree(self.dirpath)

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

        # Offest 1, limit 1.
        r = json.loads(self.app.get("/tasks/list/1/1").data)
        assert len(r["tasks"]) == 1
        assert r["tasks"][0]["id"] == 2

        # Offest 1, limit 2.
        r = json.loads(self.app.get("/tasks/list/2/1").data)
        assert len(r["tasks"]) == 2
        assert r["tasks"][0]["id"] == 2
        assert r["tasks"][1]["id"] == 3

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

    def test_delete_task(self):
        task_id = self.create_task()

        r = self.app.get("/tasks/view/%s" % task_id)
        target = json.loads(r.data)["task"]["target"]
        assert os.path.exists(target)

        Database().set_status(task_id, TASK_RUNNING)
        r = self.app.get("/tasks/delete/%s" % task_id)
        assert r.status_code == 500

        Database().set_status(task_id, TASK_COMPLETED)
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

        # Fetch by id.
        r = self.app.get("/files/view/id/%s" % task_id)
        sample = json.loads(r.data)
        assert sample["sample"]["id"] == 1

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
        Database().set_status(a, TASK_COMPLETED)

        time.sleep(1)
        t2 = int(time.time())
        Database().set_status(b, TASK_COMPLETED)

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

        Database().set_status(a, TASK_COMPLETED)

        r = json.loads(self.app.get("/tasks/list", query_string={
            "status": TASK_COMPLETED,
        }).data)
        assert len(r["tasks"]) == 1

        Database().set_status(a, TASK_COMPLETED)
        r = json.loads(self.app.get("/tasks/list", query_string={
            "status": TASK_COMPLETED,
        }).data)
        assert len(r["tasks"]) == 1

        Database().set_status(b, TASK_COMPLETED)
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

def test_bool():
    assert api.parse_bool("true") is True
    assert api.parse_bool("True") is True
    assert api.parse_bool("yes") is True
    assert api.parse_bool("1") is True

    assert api.parse_bool("false") is False
    assert api.parse_bool("False") is False
    assert api.parse_bool("None") is False
    assert api.parse_bool("no") is False
    assert api.parse_bool("0") is False

    assert api.parse_bool("2") is True
    assert api.parse_bool("3") is True
