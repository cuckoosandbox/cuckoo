# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path
import pytest
import tempfile

from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.core.database import Database
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd
from cuckoo.processing.debug import Debug
from cuckoo.processing.network import Pcap
from cuckoo.processing.network import Pcap2
from cuckoo.processing.screenshots import Screenshots
from cuckoo.processing.static import Static
from cuckoo.processing.strings import Strings
from cuckoo.processing.virustotal import VirusTotal
from cuckoo.processing.platform.windows import RebootReconstructor
db = Database()

class TestProcessing:
    def test_debug(self):
        set_cwd(tempfile.mkdtemp())

        db.connect(dsn="sqlite:///:memory:")
        db.add_url("http://google.com/")
        db.add_error("foo", 1)
        db.add_error("bar", 1)

        d = Debug()
        d.task = {
            "id": 1,
        }
        d.log_path = "nothing_to_see_here"
        d.cuckoolog_path = "neither here"
        d.mitmerr_path = "no no no"

        results = d.run()
        assert len(list(results["errors"])) == len(results["errors"])
        assert results["errors"] == ["foo", "bar"]
        assert results["action"] == []

        db.add_error("err", 1, "thisisanaction")
        results = d.run()
        assert results["action"] == ["thisisanaction"]

    def test_pdf(self):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "pdf",
            "target": "pdf0.pdf",
        })
        s.set_options({
            "pdf_timeout": 30,
        })
        s.file_path = "tests/files/pdf0.pdf"
        r = s.run()["pdf"][0]
        assert "var x = unescape" in r["javascript"][0]["orig_code"]

    def test_office(self):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "doc",
            "target": "createproc1.docm",
        })
        s.file_path = "tests/files/createproc1.docm"
        r = s.run()["office"]
        assert "ThisDocument" in r["macros"][0]["orig_code"]
        assert "Sub AutoOpen" in r["macros"][1]["orig_code"]
        assert 'process.Create("notepad.exe"' in r["macros"][1]["orig_code"]

    def test_strings(self):
        s = Strings()
        s.set_task({
            "category": "file",
        })

        fd, filepath = tempfile.mkstemp()
        os.write(fd, "ABCDEFGH\n"*0x1000)
        os.close(fd)

        s.file_path = filepath
        assert len(s.run()) == s.MAX_STRINGCNT

        fd, filepath = tempfile.mkstemp()
        os.write(fd, ("%s\n" % ("A"*0x1000)) * 200)
        os.close(fd)

        s.file_path = filepath
        strings = s.run()
        assert len(strings) == 200
        assert len(strings[0]) == s.MAX_STRINGLEN
        assert len(strings[42]) == s.MAX_STRINGLEN
        assert len(strings[199]) == s.MAX_STRINGLEN

    @mock.patch("cuckoo.processing.screenshots.log")
    def test_screenshot_tesseract(self, p):
        s = Screenshots()
        # Use an empty directory so no actual screenshot analysis is done.
        s.shots_path = tempfile.mkdtemp()
        s.set_options({
            "tesseract": None,
        })
        assert s.run() == []
        p.error.assert_not_called()

        s.set_options({
            "tesseract": "no",
        })
        assert s.run() == []
        p.error.assert_not_called()

        s.set_options({
            "tesseract": "thispathdoesnotexist",
        })
        assert s.run() == []
        p.error.assert_called_once()

    @mock.patch("cuckoo.processing.screenshots.subprocess")
    def test_screenshots(self, p):
        s = Screenshots()
        s.shots_path = os.path.join(
            "tests", "files", "sample_analysis_storage", "shots"
        )
        s.set_options({
            "tesseract": __file__,
        })
        p.check_output.return_value = "foobar"
        assert s.run() == [{
            "path": os.path.join(s.shots_path, "0001.jpg"),
            "ocr": "foobar",
        }]
        p.check_output.assert_called_once_with([
            __file__, os.path.join(s.shots_path, "0001.jpg"), "stdout"
        ])
        shotpath = os.path.join(
            "tests", "files", "sample_analysis_storage",
            "shots", "0001_small.jpg"
        )
        assert os.path.exists(shotpath)
        os.unlink(shotpath)

    @mock.patch("cuckoo.processing.screenshots.subprocess")
    @mock.patch("cuckoo.processing.screenshots.log")
    def test_ignore_notesseract(self, p, q):
        s = Screenshots()
        s.shots_path = os.path.join(
            "tests", "files", "sample_analysis_storage", "shots"
        )
        s.set_options({
            "tesseract": "no",
        })
        assert len(s.run()) == 1
        p.error.assert_not_called()
        p.warning.assert_not_called()
        q.check_output.assert_not_called()
        shotpath = os.path.join(
            "tests", "files", "sample_analysis_storage",
            "shots", "0001_small.jpg"
        )
        assert os.path.exists(shotpath)
        os.unlink(shotpath)

    def test_virustotal_nokey(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "processing": {
                "virustotal": {
                    "key": None,
                },
            },
        })
        with pytest.raises(CuckooProcessingError) as e:
            VirusTotal().run()
        e.match("API key not configured")

    def test_virustotal_invalidcategory(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        with pytest.raises(CuckooProcessingError) as e:
            v = VirusTotal()
            v.set_task({
                "category": "notacategory",
            })
            v.run()
        e.match("Unsupported task category")

class TestProcessingNetwork(object):

    def test_create_dns_server_list(self):
        res = Pcap("tests/files/pcap/used_dns_server.pcap", {}).run()
        assert res["dns_servers"] == ["8.8.8.8"]

class TestPcap2(object):

    def test_smtp_ex(self):
        pcap = Pcap2("tests/files/pcap/smtp.pcap", None, tempfile.mkdtemp())
        data = pcap.run()

        assert len(data["smtp_ex"]) == 1
        assert data["smtp_ex"][0]["req"]["username"] == "galunt"
        assert data["smtp_ex"][0]["req"]["password"] == "V1v1tr0n"
        assert data["smtp_ex"][0]["req"]["mail_to"] == ['xxxxxx.xxxx@xxxxx.com']
        assert data["smtp_ex"][0]["req"]["mail_from"] == ['xxxxxx@xxxxx.co.uk']
        assert len(data["smtp_ex"][0]["req"]["headers"]) == 10
        assert data["smtp_ex"][0]["resp"]["banner"] == "220 smtp006.mail.xxx.xxxxx.com ESMTP\r\n"

class TestPlatformWindows(object):

    def test_parse_cmdline(self):

        rb = RebootReconstructor()
        command = "Stuff.exe /Y /x -P"
        args_unicode = "\u4404\u73A8 \uECBC\uEE9E".decode("unicode-escape")
        command_unicode = "Stuff.exe " + args_unicode

        assert rb.parse_cmdline(command) == ('Stuff.exe', ['/Y', '/x', '-P'])
        assert rb.parse_cmdline(command_unicode) == ('Stuff.exe', ['\\u4404\\u73a8', '\\uecbc\\uee9e'])
