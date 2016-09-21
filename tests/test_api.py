# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import json
import os.path
import shutil
import tempfile
import werkzeug

from cuckoo.apps import api
from cuckoo.core.database import Database
from cuckoo.misc import set_cwd
from cuckoo.common.files import Folders, Files

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
        print self.dirpath

    def teardown(self):
        shutil.rmtree(self.dirpath)

    def test_list_tasks(self):
        r = json.loads(self.app.get("/tasks/list").data)
        assert r == {"tasks": []}

    def test_create_task(self):
        assert self.create_task() == 1

    def test_create_tasks(self):
        assert self.create_task() == 1
        assert self.create_task() == 2
        assert self.create_task() == 3

        r = json.loads(self.app.get("/tasks/list").data)
        assert len(r["tasks"]) == 3

        r = json.loads(self.app.get("/tasks/view/1").data)
        task = r["task"]
        assert task["category"] == "file"
        assert task["sample"]["md5"] == "f2d886558b2866065c3da842bfe13ce6"
        assert open(task["target"], "rb").read() == "eval('alert(1)')"

    def test_delete_task(self):
        task_id = self.create_task()

        r = self.app.get("/tasks/view/%s" % task_id)
        target = json.loads(r.data)["task"]["target"]
        assert os.path.exists(target)

        r = self.app.get("/tasks/delete/%s" % task_id)
        assert r.status_code == 200

        r = self.app.get("/tasks/view/%s" % task_id)
        assert r.status_code == 404

        # TODO Should the file be deleted?
        # assert not os.path.exists(target)

    def create_task(self, filename="a.js", content="eval('alert(1)')"):
        r = self.app.post("/tasks/create/file", data={
            "file": werkzeug.FileStorage(io.BytesIO(content), filename),
        })
        return json.loads(r.data)["task_id"]
