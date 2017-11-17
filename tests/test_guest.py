# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import mock
import pytest
import requests
import responses
import tempfile
import zipfile

from cuckoo.core.guest import GuestManager, OldGuestManager, analyzer_zipfile
from cuckoo.core.startup import init_yara
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd

class TestAnalyzerZipfile(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        init_yara()

    def create(self, *args):
        return zipfile.ZipFile(io.BytesIO(analyzer_zipfile(*args)))

    def test_windows(self):
        z = self.create("windows", "latest")
        l = z.namelist()
        assert "analyzer.py" in l
        assert "bin/monitor-x64.dll" in l
        assert "bin/rules.yarac" in l

        latest = open(cwd("monitor", "latest"), "rb").read().strip()
        monitor64 = open(
            cwd("monitor", latest, "monitor-x64.dll"), "rb"
        ).read()
        assert z.read("bin/monitor-x64.dll") == monitor64

    def test_linux(self):
        z = self.create("linux", None)
        l = z.namelist()
        assert "analyzer.py" in l

class TestOldGuestManager(object):
    def test_start_analysis_timeout(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "timeouts": {
                    "critical": 666,
                },
            },
        })
        gm = OldGuestManager("cuckoo1", "1.2.3.4", "windows", 1)
        gm.wait = mock.MagicMock(side_effect=Exception)
        with pytest.raises(Exception):
            gm.start_analysis({"timeout": 671}, None)
        assert gm.timeout == 1337

    @mock.patch("cuckoo.core.guest.log")
    @mock.patch("cuckoo.core.guest.time")
    @mock.patch("cuckoo.core.guest.db")
    def test_no_critical_error_at_finish(self, p, q, r):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        gm = OldGuestManager("cuckoo1", "1.2.3.4", "windows", 1)
        gm.server = mock.MagicMock()
        gm.timeout = 6
        p.guest_get_status.return_value = "running"
        q.time.side_effect = [
            1, 2, 3, 4, 5, 6, 7, 8, 9
        ]
        gm.wait_for_completion()
        assert q.time.call_count == 8
        assert "end of analysis" in r.info.call_args_list[-1][0][0]

class TestGuestManager(object):
    @responses.activate
    def test_get_exception(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        responses.add(responses.GET, "http://1.2.3.4:8000/", status=400)
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        with pytest.raises(requests.HTTPError):
            gm.get("/")

    @responses.activate
    def test_do_not_get_exception(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        responses.add(responses.GET, "http://1.2.3.4:8000/", status=501)
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        assert gm.get("/", do_raise=False).status_code == 501

    @responses.activate
    def test_post_exception(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        responses.add(responses.POST, "http://1.2.3.4:8000/store", status=500)
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        with pytest.raises(requests.HTTPError):
            gm.post("/store", data={"filepath": "hehe"})

    def test_start_analysis_timeout(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "timeouts": {
                    "critical": 123,
                },
            },
        })
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        gm.wait_available = mock.MagicMock(side_effect=Exception)
        with pytest.raises(Exception):
            gm.start_analysis({"timeout": 42}, None)
        assert gm.timeout == 165

    @mock.patch("cuckoo.core.guest.requests")
    @mock.patch("cuckoo.core.guest.log")
    @mock.patch("cuckoo.core.guest.time")
    @mock.patch("cuckoo.core.guest.db")
    def test_no_critical_error_at_finish(self, p, q, r, s):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        gm.timeout = 6
        p.guest_get_status.return_value = "running"
        q.time.side_effect = [
            1, 2, 3, 4, 5, 6, 7, 8, 9
        ]
        gm.wait_for_completion()
        assert q.time.call_count == 8
        assert "end of analysis" in r.info.call_args_list[-1][0][0]

    @responses.activate
    def test_analyzer_path(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        responses.add(responses.POST, "http://1.2.3.4:8000/mkdir", status=200)

        gm_win = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        gm_win.environ["SYSTEMDRIVE"] = "C:"
        gm_win.options["options"] = "analpath=tempdir"
        gm_win.determine_analyzer_path()

        gm_lin = GuestManager("cuckoo1", "1.2.3.4", "linux", 1, None)
        gm_lin.options["options"] = "analpath=tempdir"
        gm_lin.determine_analyzer_path()

        assert gm_lin.analyzer_path == "/tempdir"
        assert gm_win.analyzer_path == "C:/tempdir"

    def test_temp_path(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        gm_win = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        gm_win.environ["TEMP"] = "C:\\Users\\user\\AppData\\Local\\Temp"

        gm_lin = GuestManager("cuckoo1", "1.2.3.4", "linux", 1, None)

        assert gm_lin.determine_temp_path() == "/tmp"
        assert gm_win.determine_temp_path() == "C:\\Users\\user\\AppData\\Local\\Temp"

    def test_system_drive(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        gm_win = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)
        gm_win.environ["SYSTEMDRIVE"] = "C:"

        gm_lin = GuestManager("cuckoo1", "1.2.3.4", "linux", 1, None)

        assert gm_win.determine_system_drive() == "C:/"
        assert gm_lin.determine_system_drive() == "/"
