# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import ntpath
import responses
import tempfile
import zipfile

from cuckoo.common.files import Folders, Files
from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.misc import set_cwd

# TODO We can get rid of this once we don't use URLValidator anymore.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

CUCKOO_CONF = """
[cuckoo]
tmppath = /tmp
"""

PROCESSING_CONF = """
[virustotal]
enabled = yes
timeout = 60
scan = 0
key = a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088
"""

class TestSubmitManager(object):
    def setup(self):
        self.dirpath = tempfile.mkdtemp()
        set_cwd(self.dirpath)

        self.d = Database()
        self.d.connect(dsn="sqlite:///:memory:")

        Folders.create(self.dirpath, "conf")
        Files.create(self.dirpath, "conf/cuckoo.conf", CUCKOO_CONF)
        Files.create(self.dirpath, "conf/processing.conf", PROCESSING_CONF)

        self.submit_manager = SubmitManager()

        self.urls = [
            "http://theguardian.com/",
            "https://news.ycombinator.com/"
        ]

        self.hashes = [
            "ba78410702f0cc8453da1afbb2a8b670",
            "87943278943798784783974893278493",  # invalid hash
        ]

        self.files = [{
            "name": "foo.txt",
            "data": open("tests/files/foo.txt", "rb").read()
        }]

    def test_pre_file(self):
        """Tests the submission of a plaintext file"""
        assert self.submit_manager.pre(
            submit_type="files",
            data=self.files
        ) == 1

        submit = self.d.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["errors"]) == 0
        assert os.path.exists(submit.data["data"][0]["data"])

        assert submit.data["data"][0]["type"] == "file"
        filedata = open(submit.data["data"][0]["data"], "rb").read()
        assert filedata == self.files[0]["data"]

    def test_pre_url(self):
        """Tests the submission of URLs (http/https)"""
        assert self.submit_manager.pre(
            submit_type="strings",
            data=self.urls
        ) == 1

        submit = self.d.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["data"]) == 2

        url0, url1 = submit.data["data"]
        assert url0["type"] == "url"
        assert url0["data"] == "http://theguardian.com/"
        assert url1["type"] == "url"
        assert url1["data"] == "https://news.ycombinator.com/"

    @responses.activate
    def test_pre_hash(self):
        """Tests the submission of a VirusTotal hash."""
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.add(
                responses.GET, VirusTotalAPI.HASH_DOWNLOAD, body="A"*1024*1024
            )
            rsps.add(
                responses.GET, VirusTotalAPI.HASH_DOWNLOAD, status=404
            )

            assert self.submit_manager.pre(
                submit_type="strings",
                data=self.hashes
            ) == 1

            submit = self.d.view_submit(1)
            assert isinstance(submit.data["data"], list)
            assert len(submit.data["data"]) == 1

            task0, = submit.data["data"]
            assert task0["type"] == "file"
            assert open(task0["data"], "rb").read() == "A"*1024*1024

            # We couldn't locate the second hash.
            assert submit.data["errors"][0].startswith("Error retrieving")

    def test_pre_url_submit(self):
        """
        Tests the submission of URLs (http/https) and
        submits it as tasks
        """
        assert self.submit_manager.pre(
            submit_type="strings",
            data=self.urls
        ) == 1

        submit = self.d.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["data"]) == 2

        for obj in submit.data["data"]:
            assert obj["type"] == "url"

        selected_files = []
        for url in self.urls:
            selected_files.append({
                "filename": url,
                "filepath": [""],
                "package": "ie",
                "type": "url"
            })

        tasks = self.submit_manager.submit(
            submit_id=1,
            selected_files=selected_files,
            memory=False,
            priority=2,
        )

        assert len(tasks) == 2
        assert tasks[0] == 1
        assert tasks[1] == 2

        for task_id in tasks:
            url = self.urls[task_id - 1]
            view_task = self.d.view_task(task_id=task_id, details=True)

            assert view_task.target == url
            assert view_task.status == "pending"
            assert view_task.package == "ie"
            assert view_task.priority == 2
            assert view_task.memory is False
            assert view_task.id == task_id
            assert view_task.category == "url"

    def test_pre_file_submit(self):
        """
        Tests the submission of a plaintext file and submits
        it as a task
        """
        assert self.submit_manager.pre(
            submit_type="files",
            data=self.files
        ) == 1

        submit = self.d.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["errors"]) == 0
        assert os.path.exists(submit.data["data"][0]["data"])
        assert submit.data["data"][0]["type"] == "file"

        selected_files = []
        for f in self.files:
            selected_files.append({
                "filename": f["name"],
                "filepath": [""],
                "package": None,
                "type": "file"
            })

        tasks = self.submit_manager.submit(
            submit_id=1,
            selected_files=selected_files,
            memory=False,
            priority=2,
            enforce_timeout=False
        )

        assert len(tasks) == 1
        assert tasks[0] == 1

        for task_id in tasks:
            f = self.files[task_id - 1]
            view_task = self.d.view_task(task_id=task_id, details=True)

            assert view_task.target.endswith(ntpath.basename(f["name"]))
            assert view_task.status == "pending"
            assert view_task.package is None
            assert view_task.priority == 2
            assert view_task.memory is False
            assert view_task.id == task_id
            assert view_task.category == "file"
            assert open(view_task.target, "rb").read() == f["data"]

    def test_nested_archive(self):
        submit_id = self.submit_manager.pre("files", [{
            "name": "msg_invoice.msg",
            "data": open("tests/files/msg_invoice.msg", "rb").read(),
        }])

        selected_files = [
            {
                "package": "doc",
                "filename": "oledata.mso",
                "type": "container",
                "filepath": [
                    "msg_invoice.msg",
                    "oledata.mso"
                ]
            },
            {
                "package": "exe",
                "filename": "Firefox Setup Stub 43.0.1.exe",
                "type": "file",
                "filepath": [
                    "msg_invoice.msg",
                    "oledata.mso",
                    "Firefox Setup Stub 43.0.1.exe"
                ]
            }
        ]

        task_ids = self.submit_manager.submit(submit_id, selected_files)
        t0, t1 = self.d.view_task(task_ids[0]), self.d.view_task(task_ids[1])
        assert t0.category == "archive"
        assert t0.options == {
            "filename": "oledata.mso",
        }
        assert len(zipfile.ZipFile(t0.target).read("oledata.mso")) == 234898
        assert t1.category == "archive"
        assert t1.options == {
            "filename": "Firefox Setup Stub 43.0.1.exe",
        }
        assert len(zipfile.ZipFile(t1.target).read(
            "Firefox Setup Stub 43.0.1.exe"
        )) == 249336
