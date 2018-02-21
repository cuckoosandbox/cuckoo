# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import json
import mock
import os
import pytest
import responses
import tempfile
import zipfile

from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.core.database import Database
from cuckoo.core.submit import SubmitManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd

db = Database()

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

        db.connect()
        db.add_machine(
            "cuckoo1", "cuckoo2", "1.2.3.4", "windows", None, None, "int0",
            None, "5.6.7.8", 2042
        )
        self.submit_manager = SubmitManager()

    def test_pre_file(self):
        """Tests the submission of a plaintext file"""
        assert self.submit_manager.pre(submit_type="files", data=[{
            "name": "foo.txt",
            "data": open("tests/files/foo.txt", "rb").read()
        }]) == 1

        submit = db.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["errors"]) == 0
        assert os.path.exists(submit.data["data"][0]["data"])

        assert submit.data["data"][0]["type"] == "file"
        filedata = open(submit.data["data"][0]["data"], "rb").read()
        assert filedata == open("tests/files/foo.txt", "rb").read()

    def test_pre_url(self):
        """Tests the submission of URLs (http/https)"""
        assert self.submit_manager.pre(submit_type="strings", data=[
            "http://theguardian.com/",
            "https://news.ycombinator.com/",
            # Any trailing whitespaces should be stripped.
            "google.com \t",
        ]) == 1

        submit = db.view_submit(1)
        assert isinstance(submit.data["data"], list)
        assert len(submit.data["data"]) == 3

        url0, url1, url2 = submit.data["data"]
        assert url0["type"] == "url"
        assert url0["data"] == "http://theguardian.com/"
        assert url1["type"] == "url"
        assert url1["data"] == "https://news.ycombinator.com/"
        assert url2["type"] == "url"
        assert url2["data"] == "http://google.com"

    def test_invalid_strings(self):
        assert SubmitManager().pre("strings", ["thisisnotanurl"]) == 1
        submit = db.view_submit(1)
        assert len(submit.data["errors"]) == 1
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

            assert self.submit_manager.pre(submit_type="strings", data=[
                "ba78410702f0cc8453da1afbb2a8b670",
                "87943278943798784783974893278493",  # invalid hash
            ]) == 1

            submit = db.view_submit(1)
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
        t = db.view_task(1)
        assert t.target == "http://cuckoosandbox.org"
        assert t.package == "ie"
        assert t.timeout == 120
        assert t.category == "url"
        assert t.status == "pending"
        assert not t.enforce_timeout
        assert not t.memory
        assert not t.machine
        assert t.options == {
            "procmemdump": "yes",
            "route": "internet",
        }

    def test_submit_url2(self):
        assert self.submit_manager.pre(
            "strings", ["http://google.com"]
        ) == 1
        config = json.load(open("tests/files/submit/url2.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target == "http://google.com"
        assert t.package == "ie"
        assert t.timeout == 120
        assert t.category == "url"
        assert t.status == "pending"
        assert not t.enforce_timeout
        assert not t.memory
        assert not t.machine
        assert t.options == {
            "procmemdump": "yes",
            "route": "vpn0",
        }

    def test_submit_file1(self):
        assert self.submit_manager.pre("files", [{
            "name": "icardres.dll",
            "data": open("tests/files/icardres.dll", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/file1.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("icardres.dll")
        assert t.package == "dll"
        assert t.timeout == 120
        assert t.category == "file"
        assert t.status == "pending"
        assert t.enforce_timeout is True
        assert not t.memory
        assert not t.machine
        assert t.options == {
            "route": "internet",
        }

    def test_submit_file2(self):
        assert self.submit_manager.pre("files", [{
            "name": "pdf0.pdf",
            "data": open("tests/files/pdf0.pdf", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/file2.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("pdf0.pdf")
        assert t.package == "pdf"
        assert t.timeout == 111
        assert t.category == "file"
        assert t.status == "pending"
        assert t.enforce_timeout is True
        assert t.memory is True
        assert not t.machine
        assert t.options == {
            "route": "none",
            "free": "yes",
            "human": "0",
        }

    def test_submit_file3_drop(self):
        assert self.submit_manager.pre("files", [{
            "name": "msgbox.exe",
            "data": "hello world",
        }]) == 1

        config = json.load(open("tests/files/submit/file3.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("msgbox.exe")
        assert t.options == {
            "procmemdump": "yes",
            "route": "drop",
        }

    def test_submit_file4_tor(self):
        assert self.submit_manager.pre("files", [{
            "name": "msgbox.exe",
            "data": "hello world",
        }]) == 1

        config = json.load(open("tests/files/submit/file4.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("msgbox.exe")
        assert t.options == {
            "procmemdump": "yes",
            "route": "tor",
        }

    def test_submit_arc1(self):
        assert self.submit_manager.pre("files", [{
            "name": "msg_invoice.msg",
            "data": open("tests/files/msg_invoice.msg", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc1.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("msg_invoice.msg")
        assert t.package == "doc"
        assert t.timeout == 120
        assert t.category == "archive"
        assert t.status == "pending"
        assert t.machine == "cuckoo2"
        assert not t.enforce_timeout
        assert not t.memory
        assert t.options == {
            "route": "internet",
            "filename": "oledata.mso",
        }
        assert len(zipfile.ZipFile(t.target).read("oledata.mso")) == 234898

    def test_submit_arc2(self):
        assert self.submit_manager.pre("files", [{
            "name": "pdf0.zip",
            "data": open("tests/files/pdf0.zip", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc2.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("pdf0.zip")
        assert t.package == "pdf"
        assert t.timeout == 10
        assert t.category == "archive"
        assert t.status == "pending"
        assert t.machine is None
        assert not t.enforce_timeout
        assert not t.memory
        assert t.options == {
            "route": "none",
            "procmemdump": "yes",
            "filename": "files/pdf0.pdf",
        }
        assert len(zipfile.ZipFile(t.target).read("files/pdf0.pdf")) == 680

    def test_submit_arc3(self):
        assert self.submit_manager.pre("files", [{
            "name": "pdf0.tgz",
            "data": open("tests/files/pdf0.tgz", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc3.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("pdf0.zip")
        assert t.package == "pdf"
        assert t.timeout == 10
        assert t.category == "archive"
        assert t.status == "pending"
        assert t.machine is None
        assert not t.enforce_timeout
        assert not t.memory
        assert t.options == {
            "route": "none",
            "procmemdump": "yes",
            "filename": "files/pdf0.pdf",
        }
        assert len(zipfile.ZipFile(t.target).read("files/pdf0.pdf")) == 680

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_submit_arc4(self):
        assert self.submit_manager.pre("files", [{
            "name": "rar_plain.rar",
            "data": open("tests/files/rar_plain.rar", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc4.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("rar_plain.rar")
        assert t.options == {
            "route": "none",
            "procmemdump": "yes",
            "filename": "bar.txt",
        }
        assert len(zipfile.ZipFile(t.target).read("bar.txt")) == 12

    @pytest.mark.skipif("sys.platform != 'linux2'")
    def test_submit_arc5(self):
        assert self.submit_manager.pre("files", [{
            "name": "rar_plain_rar.rar",
            "data": open("tests/files/rar_plain_rar.rar", "rb").read(),
        }]) == 1

        config = json.load(open("tests/files/submit/arc5.json", "rb"))
        assert self.submit_manager.submit(1, config) == [1]
        t = db.view_task(1)
        assert t.target.endswith("rar_plain.rar")
        assert t.options == {
            "route": "none",
            "procmemdump": "yes",
            "filename": "bar.txt",
        }
        assert len(zipfile.ZipFile(t.target).read("bar.txt")) == 12

    def test_pre_options(self):
        assert self.submit_manager.pre(
            "strings", ["google.com"], {"foo": "bar"}
        ) == 1
        assert db.view_submit(1).data["options"] == {"foo": "bar"}

    def sample_analysis(self):
        # Copied from test_web::test_import_analysis.
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
        return z, buf

    @mock.patch("cuckoo.core.submit.log")
    def test_import_analysis_json(self, p):
        z, buf = self.sample_analysis()
        z.writestr("analysis.json", json.dumps({
            "errors": "nope",
        }))
        z.close()
        buf.seek(0)

        self.submit_manager.import_(buf, None)
        p.warning.assert_called_once()

        z, buf = self.sample_analysis()
        z.writestr("analysis.json", json.dumps({
            "errors": ["yes", "very", "error"],
            "action": ["oneaction"],
        }))
        z.close()
        buf.seek(0)

        task_id = self.submit_manager.import_(buf, None)
        errors = [(e.message, e.action) for e in db.view_errors(task_id)]
        assert sorted(errors) == [
            ("", "oneaction"), ("error", None), ("very", None), ("yes", None),
        ]

def test_option_translations_from():
    sm = SubmitManager()

    assert sm.translate_options_from({}, {}) == {}

    assert sm.translate_options_from({}, {
        "simulated-human-interaction": True,
    }) == {}
    assert sm.translate_options_from({}, {
        "simulated-human-interaction": False,
    }) == {
        "human": 0,
    }

    assert sm.translate_options_from({}, {
        "enable-injection": False,
    }) == {
        "free": "yes",
    }
    assert sm.translate_options_from({}, {
        "enable-injection": True,
    }) == {}

    assert sm.translate_options_from({
        "network-routing": "foobar",
    }, {}) == {
        "route": "foobar",
    }

    assert sm.translate_options_from({}, {
        "enable-injection": False,
        "key": "value",
    }) == {
        "free": "yes",
        "key": "value",
    }

    assert sm.translate_options_from({}, {
        "remote-control": True,
    }) == {
        "remotecontrol": "yes",
    }

def test_option_translations_to():
    sm = SubmitManager()

    assert sm.translate_options_to({}) == {}

    assert sm.translate_options_to({
        "human": "0",
    }) == {
        "simulated-human-interaction": False,
    }

    assert sm.translate_options_to({
        "free": "yes",
    }) == {
        "enable-injection": False,
    }

    assert sm.translate_options_to({
        "remotecontrol": "yes",
    }) == {
        "remote-control": True,
    }
