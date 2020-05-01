# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import sys
import pytest
import tempfile
import subprocess

from cuckoo.common.objects import Dictionary
from cuckoo.common.config import Config, config
from cuckoo.machinery.avd import Avd
from cuckoo.common.files import Folders
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.misc import set_cwd, cwd
from cuckoo.common.exceptions import CuckooMachineError

class TestAvd(object):

    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = Avd()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("avd"))

    def test_stop_no_emu_labels(self):
        self.m._emulator_labels = {}
        with pytest.raises(CuckooMachineError) as e:
            self.m.stop("cuckoo")
        e.match("Trying to stop a machine that wasn't started")

    def test_stop_success(self):
        self.m._emulator_labels = {"cuckoo": "emulator-1337"}

        with mock.patch("cuckoo.machinery.avd.subprocess.Popen") as p:
            proc = mock.MagicMock()
            proc.communicate.return_value = "", ""
            proc.returncode = 0
            p.return_value = proc

            self.m.stop("cuckoo")

        p.assert_called_once_with([
            "sudo", config("avd:avd:adb_path"),
            "-s", "emulator-1337",
            "emu", "kill"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        assert self.m._emulator_labels == {}

    def test_stop_failure(self):
        self.m._emulator_labels = {"cuckoo": "emulator-1337"}

        with mock.patch("cuckoo.machinery.avd.subprocess.Popen") as p:
            proc = mock.MagicMock()
            proc.communicate.return_value = "", ""
            proc.returncode = -1
            p.return_value = proc

            with pytest.raises(CuckooMachineError) as e:
                self.m.stop("cuckoo")

        e.match("Emulator failed to stop the machine")

    def test_start_snapshot_headless(self):
        self.m._emulator_labels = {}
        self.m._wait_status_ready = mock.MagicMock()

        class named_machine(object):
            name = "cuckoo"
            label = "cuckoo"
            options = ["headless"]
            snapshot = "cuckoo_snapshot"

        self.m.db.view_machine_by_label.return_value = named_machine()
        self.m.db.list_machines.return_value = [named_machine()]

        with mock.patch("cuckoo.machinery.avd.subprocess.Popen") as subprocess_popen:
            proc = mock.MagicMock()
            proc.poll.return_value = None
            proc.communicate.return_value = "", ""
            subprocess_popen.return_value = proc

            with mock.patch("cuckoo.machinery.avd.socket.socket") as s:
                emu_sock = mock.MagicMock()
                emu_sock.fileno.return_value = sys.stdout.fileno()
                emu_sock.recv.return_value = 1337

                s.return_value = mock.MagicMock()
                s.return_value.fileno.return_value = sys.stdout.fileno()
                s.return_value.accept.return_value = [emu_sock, None]

                self.m.start("cuckoo", None)

        assert subprocess_popen.call_count == 1
        assert s.return_value.accept.call_count == 1
        assert emu_sock.recv.call_count == 1
        assert self.m._emulator_labels <= set(["cuckoo", "emulator-1337"])
        assert set(["-no-audio", "-no-window"]) <= set(subprocess_popen.call_args[0][0])
        assert set(["-snapshot", "cuckoo_snapshot"]) <= set(subprocess_popen.call_args[0][0])
