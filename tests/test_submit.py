# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os
import responses
import tempfile
import zipfile

from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd

class TestSubmitManager(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "processing": {
                "virustotal": {
                    "enabled": True,
                },
            },
        })

        self.db = Database()
        self.db.connect()

        self.submit_manager = SubmitManager()

        self.urls = [
            "http://theguardian.com/",
            "https://news.ycombinator.com/",
            "google.com",
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

        submit = self.db.view_submit(1)
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

        submit = self.db.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["data"]) == 3

        url0, url1, url2 = submit.data["data"]
        assert url0["type"] == "url"
        assert url0["data"] == "http://theguardian.com/"
        assert url1["type"] == "url"
        assert url1["data"] == "https://news.ycombinator.com/"
        assert url2["type"] == "url"
        assert url2["data"] == "google.com"

    def test_invalid_strings(self):
        assert SubmitManager().pre("strings", "thisisnotanurl") == 1
        submit = self.db.view_submit(1)
        assert "was neither a valid hash or url" in submit.data["errors"][0]
        assert not submit.data["data"]

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

            submit = self.db.view_submit(1)
            assert isinstance(submit.data["data"], list)
            assert len(submit.data["data"]) == 1

            task0, = submit.data["data"]
            assert task0["type"] == "file"
            assert open(task0["data"], "rb").read() == "A"*1024*1024

            # We couldn't locate the second hash.
            assert submit.data["errors"][0].startswith("Error retrieving")

    def test_submit_url1(self):
        assert self.submit_manager.pre(
            "strings", ["http://cuckoosandbox.org"]
        ) == 1
        config = json.load(open("tests/files/submit/url1.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = self.db.view_task(1)
        assert t.target == "http://cuckoosandbox.org"
        assert t.package == "ie"
        assert t.timeout == 120
        assert t.category == "url"
        assert t.status == "pending"
        assert not t.machine
        assert t.options == {}

    def test_submit_file1(self):
        assert self.submit_manager.pre("files", [{
            "name": "icardres.dll",
            "data": open("tests/files/icardres.dll", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/file1.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = self.db.view_task(1)
        assert t.target.endswith("icardres.dll")
        assert t.package == "dll"
        assert t.timeout == 120
        assert t.category == "file"
        assert t.status == "pending"
        assert not t.machine
        assert t.options == {}

    def test_submit_arc1(self):
        assert self.submit_manager.pre("files", [{
            "name": "msg_invoice.msg",
            "data": open("tests/files/msg_invoice.msg", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc1.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = self.db.view_task(1)
        assert t.target.endswith("msg_invoice.msg")
        assert t.package == "doc"
        assert t.timeout == 120
        assert t.category == "archive"
        assert t.status == "pending"
        assert not t.machine
        assert t.options == {
            "filename": "oledata.mso",
        }
        assert len(zipfile.ZipFile(t.target).read("oledata.mso")) == 234898
