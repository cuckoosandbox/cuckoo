# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import logging
import pytest
import subprocess
import tempfile

from cuckoo.common.config import config, Config
from cuckoo.common.exceptions import CuckooMachineError, CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineSnapshotError
from cuckoo.common.files import Folders
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.machinery.virtualbox import VirtualBox
from cuckoo.misc import set_cwd, cwd

class TestVirtualbox(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        logging.basicConfig(level=logging.DEBUG)

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = VirtualBox()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("virtualbox"))

    def test_invalid_vboxmanage_configuration(self):
        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "path": None,
        }):
            with pytest.raises(CuckooCriticalError):
                self.m._initialize_check()

        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "path": "THIS PATH DOES NOT EXIST 404",
        }):
            with pytest.raises(CuckooCriticalError):
                self.m._initialize_check()

        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "mode": "foobar",
        }):
            with pytest.raises(CuckooCriticalError):
                self.m._initialize_check()

    def test_status_vboxmanage_failure(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = ("", "")
            p.return_value.returncode = 42
            assert self.m._status("label") == self.m.ERROR

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"),
            "showvminfo", "label", "--machinereadable"
        )
        self.m.db.set_machine_status.assert_called_once_with(
            "label", self.m.ERROR
        )

    def test_status_vboxmanage_incomplete_info(self):
        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = ("", "")
                p.return_value.returncode = 0
                self.m._status("label")

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"),
            "showvminfo", "label", "--machinereadable"
        )

    def test_status_vboxmanage_success(self):
        vmstate = (
            'biossystemtimeoffset=0\n'
            'rtcuseutc="off"\n'
            'hwvirtex="on"\n'
            'nestedpaging="on"\n'
            'largepages="off"\n'
            'VMState="poweroff"\n'
            'vtxvpid="on"\n'
            'vtxux="on"\n'
        )

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = vmstate, ""
            p.return_value.returncode = 0
            assert self.m._status("label") == "poweroff"

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"),
            "showvminfo", "label", "--machinereadable"
        )
        self.m.db.set_machine_status.assert_called_once_with(
            "label", "poweroff"
        )

    def test_status_vboxmanage_incomplete_info2(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = OSError("foobar")
            assert self.m._status("label") == self.m.ERROR

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"),
            "showvminfo", "label", "--machinereadable"
        )

    def test_list_success(self):
        output = (
            '"cuckoo1" {83294578-bf54-427c-8fce-502ddbbcc888}\n'
            '"cuckoo7" {92438051-bf54-427c-8fce-abcd78789999}\n'
        )
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = output, ""
            assert self.m._list() == ["cuckoo1", "cuckoo7"]

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"), "list", "vms"
        )

    def test_list_oserror(self):
        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                assert self.m._list() == ["cuckoo1", "cuckoo7"]

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"), "list", "vms"
        )

    def test_list_inaccessible(self):
        output = (
            '"<inaccessible>" {83294578-bf54-427c-8fce-502ddbbcc888}\n'
            '"cuckoo7" {92438051-bf54-427c-8fce-abcd78789999}\n'
        )
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = output, ""
            assert self.m._list() == ["cuckoo7"]

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"), "list", "vms"
        )

    def test_start_running(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        with pytest.raises(CuckooMachineError):
            self.m.start("label", None)

    def test_start_no_snapshot(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.start("label", None)

        p.assert_has_calls([
            mock.call(
                [
                    config("virtualbox:virtualbox:path"),
                    "snapshot", "label", "restorecurrent"
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ),
            mock.call(
                [
                    config("virtualbox:virtualbox:path"),
                    "startvm", "label", "--type", "headless",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            )
        ])

    def test_start_with_snapshot(self):
        class machine_with_snapshot(object):
            snapshot = "snapshot"
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_with_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.start("label", None)

        p.assert_any_call(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restore", "snapshot"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_start_restore_currentsnapshot_error(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                p.return_value.returncode = 42
                self.m.start("label", None)

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_start_restore_oserror(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                self.m.start("label", None)

        p.assert_any_call(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_start_startvm_oserror(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", "error starting"

        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = p1, p2
                self.m.start("label", None)

        p.assert_any_call(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_start_restore_with_snapshot_error(self):
        class machine_with_snapshot(object):
            snapshot = "snapshot"
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_with_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                p.return_value.returncode = 42
                self.m.start("label", None)

        p.assert_any_call(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restore", "snapshot"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_stop_invalid_status(self):
        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        with pytest.raises(CuckooMachineError):
            self.m.stop("label")

        self.m._status.return_value = self.m.ABORTED
        with pytest.raises(CuckooMachineError):
            self.m.stop("label")

    def test_stop_success(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._wait_status = mock.MagicMock(return_value=None)

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.poll.return_value = True
            p.returncode = 0
            self.m.stop("label")

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "controlvm", "label", "poweroff"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_stop_failure(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._wait_status = mock.MagicMock(return_value=None)

        def poll():
            return True if p["Popen"].return_value.terminate.call_count else None

        with mock.patch.multiple(
            "cuckoo.machinery.virtualbox",
            time=mock.DEFAULT, Popen=mock.DEFAULT
        ) as p:
            p["time"].sleep.return_value = None
            p["Popen"].return_value.poll.side_effect = poll
            p["Popen"].return_value.terminate.return_value = None
            p["Popen"].return_value.returncode = 0
            self.m.stop("label")

        p["Popen"].assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "controlvm", "label", "poweroff"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )
        p["Popen"].return_value.terminate.assert_called_once()

    def test_dump_pcap(self):
        class task(object):
            id = 1234

        with mock.patch("subprocess.call") as p:
            p.side_effect = 0, 0
            self.m.dump_pcap("label", task())

        p.assert_has_calls([
            mock.call([
                config("virtualbox:virtualbox:path"),
                "controlvm", "label", "nictracefile1",
                cwd("storage", "analyses", "1234", "dump.pcap")
            ]),
            mock.call([
                config("virtualbox:virtualbox:path"),
                "controlvm", "label", "nictrace1", "on"
            ])
        ])

        with mock.patch("subprocess.call") as p:
            p.side_effect = 1,
            self.m.dump_pcap("label", task())

        p.assert_called_once()

        with mock.patch("subprocess.call") as p:
            p.side_effect = 0, 1
            self.m.dump_pcap("label", task())

        assert len(p.call_args_list) == 2

    def test_dump_memory_vbox4(self):
        p1 = mock.MagicMock()
        p1.communicate.return_value = "4.3.40r110317", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.wait.return_value = None

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.dump_memory("label", "memory.dmp")

        p.assert_has_calls([
            mock.call(
                [config("virtualbox:virtualbox:path"), "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ),
            mock.call(
                [
                    config("virtualbox:virtualbox:path"),
                    "debugvm", "label", "dumpguestcore",
                    "--filename", "memory.dmp"
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ),
        ])

    def test_dump_memory_vbox5(self):
        p1 = mock.MagicMock()
        p1.communicate.return_value = "5.0.28r111378", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.wait.return_value = None

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.dump_memory("label", "memory.dmp")

        p.assert_has_calls([
            mock.call(
                [config("virtualbox:virtualbox:path"), "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ),
            mock.call(
                [
                    config("virtualbox:virtualbox:path"),
                    "debugvm", "label", "dumpvmcore",
                    "--filename", "memory.dmp"
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ),
        ])

    def test_dump_memory_oserror(self):
        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                self.m.dump_memory("label", "memory.dmp")

        p1 = mock.MagicMock()
        p1.communicate.return_value = "5.0.28r111378", ""
        p1.returncode = 0

        with pytest.raises(CuckooMachineError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = p1, OSError("foobar")
                self.m.dump_memory("label", "memory.dmp")

        # TODO Properly handle "vboxmanage -v" returning an error status code.

class TestBrokenMachine(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        logging.basicConfig(level=logging.DEBUG)

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = VirtualBox()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("virtualbox"))

    def test_missing_snapshot(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = {}

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()

        p1 = mock.MagicMock()
        p1.wait.return_value = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with pytest.raises(CuckooMachineSnapshotError):
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                self.m.start("label", None)

        p.assert_called_once_with(
            [
               config("virtualbox:virtualbox:path"),
               "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )
