# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import pytest
import requests
import responses
import tempfile

from cuckoo.core.guest import GuestManager, OldGuestManager
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd

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

    def prepare_mocks_start_analysis(self, machine, ip, os, taskid,
                                     analysis_manager):

        gm = GuestManager(machine, ip, os, taskid, analysis_manager)

        gm.wait_available = mock.MagicMock(return_value=None)
        gm.query_environ = mock.MagicMock(return_value=None)
        gm.upload_analyzer = mock.MagicMock(return_value=None)
        gm.add_config = mock.MagicMock(return_value=None)
        gm.analysis_manager.aux = mock.MagicMock()
        gm.analysis_manager.aux.callback = mock.MagicMock()
        gm.aux.callback = mock.MagicMock(return_value=None)
        gm.post = mock.MagicMock(return_value=None)
        gm.environ = {"TEMP": "C:\\Users\\A\\AppData\\local\\Temp"}

        return gm

    @responses.activate
    @mock.patch("cuckoo.core.guest.config")
    @mock.patch("cuckoo.core.guest.Database.guest_get_status")
    def test_start_analysis_first_exp_run(self, mock_get_status, mock_config):
        set_cwd(tempfile.mkdtemp())

        gm = self.prepare_mocks_start_analysis(
            "cuckoo1", "1.2.3.4", "DogeOS", 1, mock.MagicMock()
        )

        responses.add(responses.GET, "http://1.2.3.4:8000/", status=200,
                      json={"version": 2, "features": []})

        mock_config.return_value = 0

        options = {
            "timeout": 60, "experiment": 0, "category": "file",
            "file_name": "file.exe", "target": "/files/file.exe"
        }

        mock_get_status.return_value = "starting"
        mocked_open = mock.mock_open(read_data="data")
        with mock.patch("__builtin__.open", mocked_open):
            gm.start_analysis(options, None)

        gm.wait_available.assert_called_once()
        gm.query_environ.assert_called_once()
        gm.upload_analyzer.assert_called_once()
        gm.add_config.assert_called_once()
        gm.analysis_manager.aux.callback.assert_called_once_with(
            "prepare_guest"
        )

        gm.post.assert_has_calls([
            mock.call("/store", files=mock.ANY, data=mock.ANY),
            mock.call("/execute", data=mock.ANY)
        ])

    @responses.activate
    @mock.patch("cuckoo.core.guest.config")
    @mock.patch("cuckoo.core.guest.Database.guest_get_status")
    def test_start_analysis_non_first_exp_run(self, mock_get_status,
                                              mock_config):
        """The sample that is being analyzed should only be uploaded the first
        run of an experiment."""
        set_cwd(tempfile.mkdtemp())

        gm = self.prepare_mocks_start_analysis("cuckoo1", "1.2.3.4", "DogeOS",
                                               2, mock.MagicMock())

        responses.add(responses.GET, "http://1.2.3.4:8000/", status=200,
                      json={"version": 2, "features": []})

        mock_config.return_value = 0

        options = {
            "timeout": 60, "experiment": 1, "category": "file",
            "file_name": "file.exe", "target": "/files/file.exe"
        }

        mock_get_status.return_value = "starting"

        gm.start_analysis(options, None)

        gm.wait_available.assert_called_once()
        gm.query_environ.assert_called_once()
        gm.upload_analyzer.assert_called_once()
        gm.add_config.assert_called_once()
        gm.analysis_manager.aux.callback.assert_called_once_with(
            "prepare_guest"
        )

        gm.post.assert_called_once_with("/execute", data=mock.ANY)

    @responses.activate
    @mock.patch("cuckoo.core.guest.random_string")
    @mock.patch("cuckoo.core.guest.config")
    @mock.patch("cuckoo.core.guest.Database.guest_get_status")
    def test_start_analysis_first_exp_run_windows(self, mock_get_status,
                                                  mock_config, mock_rand_str):
        """First run of an experiment should create a HKLM run key for agent.py
        if the platform is Windows"""
        set_cwd(tempfile.mkdtemp())

        gm = self.prepare_mocks_start_analysis("cuckoo1", "1.2.3.4", "windows",
                                               1, mock.MagicMock())
        gm.query_agent_path = mock.MagicMock(return_value="C:\\agent.py")

        responses.add(responses.GET, "http://1.2.3.4:8000/", status=200,
                      json={"version": 2, "features": []})

        mock_config.return_value = 0

        options = {
            "timeout": 60, "experiment": 0, "category": "file",
            "file_name": "file.exe", "target": "/files/file.exe"
        }

        mock_get_status.return_value = "starting"
        mock_rand_str.return_value = "doges42"

        reg_add_data = {
            "command": "C:\\Windows\\System32\\reg.exe add "
                       "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\"
                       "CurrentVersion\\Run /v doges42"
                       " /t REG_SZ /d \"C:\\Python27\\pythonw.exe"
                       " C:\\agent.py\""
        }

        mocked_open = mock.mock_open(read_data="data")
        with mock.patch("__builtin__.open", mocked_open):
            gm.start_analysis(options, None)

        gm.wait_available.assert_called_once()
        gm.query_environ.assert_called_once()
        gm.upload_analyzer.assert_called_once()
        gm.add_config.assert_called_once()
        gm.query_agent_path.assert_called_once()
        gm.analysis_manager.aux.callback.assert_called_once_with(
            "prepare_guest"
        )

        gm.post.assert_has_calls([
            mock.call("/store", files=mock.ANY, data=mock.ANY),
            mock.call("/execute", data=reg_add_data),
            mock.call("/execute", data=mock.ANY)
        ])

    @responses.activate
    def test_query_agent_path(self):
        gm = GuestManager("cuckoo1", "1.2.3.4", "windows", 1, None)

        responses.add(responses.GET, "http://1.2.3.4:8000/path", status=200,
                      json={"filepath": "C:\\tguIK\\"})

        path = gm.query_agent_path()

        assert path == "C:\\tguIK\\"
        assert gm.agent_path == "C:\\tguIK\\"
