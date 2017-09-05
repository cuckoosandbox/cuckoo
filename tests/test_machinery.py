# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import pytest
import subprocess
import tempfile

from cuckoo.common import abstracts
from cuckoo.common.config import config, Config
from cuckoo.common.exceptions import  (
    CuckooMachineError, CuckooCriticalError, CuckooMachineSnapshotError,
    CuckooDependencyError, CuckooMissingMachineError
)
from cuckoo.common.files import Folders, Files
from cuckoo.common.objects import Dictionary
from cuckoo.core.database import Database
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.startup import init_logging
from cuckoo.machinery import xenserver, vsphere
from cuckoo.machinery.esx import ESX
from cuckoo.machinery.virtualbox import VirtualBox
from cuckoo.machinery.vmware import VMware
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd, mkdir

db = Database()


class TestVirtualbox(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = VirtualBox()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("virtualbox"))

    def test_invalid_vboxmanage_configuration(self):
        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "path": None,
        }):
            with pytest.raises(CuckooCriticalError) as e:
                self.m._initialize_check()
            e.match("VBoxManage path is missing")

        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "path": "THIS PATH DOES NOT EXIST 404",
        }):
            with pytest.raises(CuckooCriticalError) as e:
                self.m._initialize_check()
            e.match("not found at")

        with mock.patch.dict(self.m.options.virtualbox.__dict__, {
            "mode": "foobar", "path": __file__,
        }):
            with pytest.raises(CuckooCriticalError) as e:
                self.m._initialize_check()
            e.match("run in a non-supported mode")

    def test_status_vboxmanage_failure(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = "", ""
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
        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = ("", "")
                p.return_value.returncode = 0
                self.m._status("label")
        e.match("Unable to get")

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

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = vmstate, ""
            p.return_value.returncode = 0
            assert self.m.vminfo("label", "VMState") == "poweroff"
            assert self.m.vminfo("label", "biossystemtimeoffset") == "0"
            assert self.m.vminfo("label", "notanoption") is None

    def test_status_vboxmanage_incomplete_info2(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = OSError("foobar")
            assert self.m._status("label") == self.m.ERROR

        p.assert_called_once()
        p.call_args_list[0] = (
            config("virtualbox:virtualbox:path"),
            "showvminfo", "label", "--machinereadable"
        )

    @mock.patch("cuckoo.machinery.virtualbox.Popen")
    def test_vminfo_missing_machine(self, p):
        stderr = (
            "VBoxManage: error: Could not find a registered machine named 'vmname'\n"
            "VBoxManage: error: Details: code VBOX_E_OBJECT_NOT_FOUND (0x80bb0001), component VirtualBox, interface IVirtualBox, callee nsISupports\n"
            "VBoxManage: error: Context: \"FindMachine(Bstr(VMNameOrUuid).raw(), machine.asOutParam())\" at line 2611 of file VBoxManageInfo.cpp\n"
        )

        p.return_value.returncode = 1
        p.return_value.communicate.return_value = "out", stderr
        with pytest.raises(CuckooMissingMachineError) as e:
            self.m.vminfo("vmname", None)
        e.match("Please create one or more")

    @mock.patch("cuckoo.machinery.virtualbox.Popen")
    def test_initialize_snapshot_fail(self, p):
        self.m.set_options(Dictionary({
            "virtualbox": Dictionary({
                "machines": ["machine1"],
                "path": __file__,
                "mode": "headless",
            }),
            "machine1": Dictionary({
                "label": "machine1",
                "platform": "windows",
                "ip": "192.168.56.101",
                "tags": "",
                "resultserver_port": 2042,
            }),
        }))
        self.m._list = mock.MagicMock(return_value=[
            "machine1",
        ])
        self.m.stop = mock.MagicMock()
        p.return_value.returncode = 1
        p.return_value.communicate.return_value = "out", "err"

        class machine1(object):
            label = "machine1"
            snapshot = None

        self.m.machines = mock.MagicMock(return_value=[
            machine1(),
        ])
        with pytest.raises(CuckooMachineError) as e:
            self.m.initialize("virtualbox")
        e.match("trying to restore the snapshot")

    @mock.patch("cuckoo.machinery.virtualbox.Popen")
    def test_initialize_success(self, p):
        self.m.set_options(Dictionary({
            "virtualbox": Dictionary({
                "machines": ["machine1"],
                "path": __file__,
                "mode": "headless",
            }),
            "machine1": Dictionary({
                "label": "machine1",
                "platform": "windows",
                "ip": "192.168.56.101",
                "tags": "",
                "resultserver_port": 2042,
            }),
        }))
        self.m._list = mock.MagicMock(return_value=[
            "machine1",
        ])
        self.m.stop = mock.MagicMock()
        self.m._status = mock.MagicMock(return_value="poweroff")
        p.return_value.returncode = 0
        p.return_value.communicate.return_value = "", ""

        class machine1(object):
            label = "machine1"
            snapshot = None

        self.m.machines = mock.MagicMock(return_value=[
            machine1(),
        ])
        self.m.initialize("virtualbox")
        p.assert_called_once_with(
            [__file__, "snapshot", "machine1", "restorecurrent"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
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
        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                self.m._list()
        e.match("error listing installed")

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
        with pytest.raises(CuckooMachineError) as e:
            self.m.start("label", None)
        e.match("Trying to start an")

    def test_start_no_snapshot(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = []
            rdp_port = None

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
            options = []
            rdp_port = None

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
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                p.return_value.returncode = 42
                self.m.start("label", None)
        e.match("failed trying to restore")

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_start_non_revert(self):
        class machine_with_snapshot(object):
            snapshot = "snapshot"
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_with_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)
        self.m.vminfo = mock.MagicMock(return_value="label_hdd")

        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.start("label", None, revert=False)

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "startvm", "label", "--type", "headless",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_compact_hd(self):
        self.m.vminfo = mock.MagicMock(return_value="\"30d29d87-e54d\"")

        c1 = mock.MagicMock()
        c1.returncode = 0
        c1.return_value = "", ""

        with mock.patch("subprocess.check_output") as co:
            co.side_effect = c1
            self.m.compact_hd("label")

        co.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"), "modifyhd",
                "30d29d87-e54d", "--compact"
            ], stderr=subprocess.PIPE
        )

    def test_start_with_rdp(self):
        class machine_with_snapshot(object):
            snapshot = "snapshot"
            options = []
            rdp_port = 3390

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_with_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)
        self.m.restore = mock.MagicMock(return_value=None)

        c1 = mock.MagicMock()
        c1.returncode = 0
        c1.return_value = "", ""
        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            with mock.patch("subprocess.check_output") as co:
                p.side_effect = p1, p2
                co.side_effect = c1
                self.m.start("label", None)

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "startvm", "label", "--type", "headless",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

        co.assert_has_calls([
            mock.call(
                [
                    config("virtualbox:virtualbox:path"), "controlvm", "label",
                    "vrde", "on"
                ]
            ),
            mock.call(
                [
                    config("virtualbox:virtualbox:path"), "controlvm", "label",
                    "vrdeport", "3390"
                ]
            )
        ])

    def test_start_restore_oserror(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                self.m.start("label", None)
        e.match("failed trying to restore")

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
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        p1 = mock.MagicMock()
        p1.communicate.return_value = "", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", "error starting"

        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = p1, p2
                self.m.start("label", None)
        e.match("failed starting the machine")

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
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_with_snapshot()
        self.m._wait_status = mock.MagicMock(return_value=None)

        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                p.return_value.returncode = 42
                self.m.start("label", None)
        e.match("failed trying to restore")

        p.assert_any_call(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restore", "snapshot"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_safe_stop_true(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._wait_status = mock.MagicMock(return_value=None)
        self.m._safe_stop = mock.MagicMock(return_value=True)
        self.m.stop("label", safe=True)

        self.m._safe_stop.assert_called_once_with("label")

    def test_safe_stop_true_fail(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._wait_status = mock.MagicMock(return_value=None)
        self.m._safe_stop = mock.MagicMock(return_value=False)

        p1 = mock.MagicMock()
        p1.returncode = 0
        p1.poll.return_value = 0

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1
            self.m.stop("label", safe=True)

        self.m._safe_stop.assert_called_once_with("label")

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "controlvm", "label", "poweroff"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_safe_stop(self):
        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)

        p1 = mock.MagicMock()
        p1.returncode = 0
        p1.poll.return_value = 0

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1
            ret = self.m._safe_stop("label")

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"), "controlvm", "label",
                "acpipowerbutton"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

    def test_stop_invalid_status(self):
        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        with pytest.raises(CuckooMachineError) as e:
            self.m.stop("label")
        e.match("Trying to stop an already stopped")

        self.m._status.return_value = self.m.ABORTED
        with pytest.raises(CuckooMachineError) as e:
            self.m.stop("label")
        e.match("Trying to stop an already stopped")

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

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            self.m._status.return_value = self.m.SAVED
            self.m.stop("label")
            p.assert_not_called()

    def test_stop_failure(self):
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._wait_status = mock.MagicMock(return_value=None)

        def poll():
            return True if p[
                "Popen"].return_value.terminate.call_count else None

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
        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = OSError("foobar")
                self.m.dump_memory("label", "memory.dmp")
        e.match("failed to return its version")

        p1 = mock.MagicMock()
        p1.communicate.return_value = "5.0.28r111378", ""
        p1.returncode = 0

        with pytest.raises(CuckooMachineError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.side_effect = p1, OSError("foobar")
                self.m.dump_memory("label", "memory.dmp")
        e.match("failed to take a memory dump")

        # TODO Properly handle "vboxmanage -v" returning an error status code.

    def test_dump_memory_unicode(self):
        p1 = mock.MagicMock()
        p1.communicate.return_value = "5.0.28r111378", ""
        p1.returncode = 0

        p2 = mock.MagicMock()
        p2.wait.return_value = None

        mkdir(cwd(analysis=1))
        task_log_start(1)
        init_logging(logging.DEBUG)

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.side_effect = p1, p2
            self.m.dump_memory("label", u"mem\u202eory.dmp")
        task_log_stop(1)

class TestBrokenMachine(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = VirtualBox()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("virtualbox"))

    def test_missing_snapshot(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = []
            rdp_port = None

        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m.db.view_machine_by_label.return_value = machine_no_snapshot()

        p1 = mock.MagicMock()
        p1.wait.return_value = 0

        p2 = mock.MagicMock()
        p2.communicate.return_value = "", ""

        with pytest.raises(CuckooMachineSnapshotError) as e:
            with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
                p.return_value.communicate.return_value = "", "error!"
                self.m.start("label", None)
        e.match("failed trying to restore")

        p.assert_called_once_with(
            [
                config("virtualbox:virtualbox:path"),
                "snapshot", "label", "restorecurrent"
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )


def test_esx_not_installed():
    with pytest.raises(CuckooDependencyError) as e:
        ESX()
    e.match("libvirt package has not")

class TestVirtualboxInitialize(object):
    def test_initialize_global(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "cuckoo": {
                    "machinery": "virtualbox",
                },
                # This unittest will actually start the ResultServer.
                "resultserver": {
                    "ip": "127.0.0.1",
                    "port": 3000,
                },
            },
        })
        db.connect()

        self.m = VirtualBox()
        self.m.set_options(Config("virtualbox"))
        self.m._initialize("virtualbox")

        m, = db.list_machines()
        assert m.label == "cuckoo1"
        assert m.interface == "vboxnet0"
        assert m.ip == "192.168.56.101"
        assert m.options == []
        assert m.platform == "windows"
        assert m.resultserver_ip == "127.0.0.1"
        assert m.resultserver_port == 3000
        assert m.tags == []

    def test_initialize_specific(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "cuckoo": {
                    "machinery": "virtualbox",
                },
            },
            "virtualbox": {
                "cuckoo1": {
                    "label": "kookoo1",
                    "platform": "foobar",
                    "snapshot": "snapshot1",
                    "interface": "foo0",
                    "ip": "1.2.3.5",
                    "resultserver_ip": "1.2.3.4",
                    "resultserver_port": 1234,
                    # TODO Turn tags into a list.
                    "tags": "tag1,tag2",
                },
            },
        })
        db.connect()

        self.m = VirtualBox()
        self.m.set_options(Config("virtualbox"))
        self.m._initialize("virtualbox")

        m, = db.list_machines()
        assert m.label == "kookoo1"
        assert m.platform == "foobar"
        assert m.snapshot == "snapshot1"
        assert m.interface == "foo0"
        assert m.ip == "1.2.3.5"
        assert m.resultserver_ip == "1.2.3.4"
        assert m.resultserver_port == 1234
        assert sorted((t.name for t in m.tags)) == [
            "tag1", "tag2"
        ]

class TestVMWare(object):
    class task(object):
        def __init__(self):
            self.id = 1

    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = VMware()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("vmware"))

    @mock.patch("cuckoo.machinery.vmware.subprocess.Popen")
    def test_start(self, mock_popen):
        mock_popen.return_value.communicate.return_value = ("", "")

        self.m._snapshot_from_vmx = mock.MagicMock(return_value="snapshot")
        self.m._is_running = mock.MagicMock(return_value=False)
        self.m._revert = mock.MagicMock()

        self.m.start("/vmx/vm1.vmx", TestVMWare.task(), revert=True)

        self.m._revert.assert_called_once_with("/vmx/vm1.vmx", "snapshot")
        mock_popen.assert_called_once_with(
            [self.m.options.vmware.path, "start", "/vmx/vm1.vmx",
             self.m.options.vmware.mode], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.Popen")
    def test_start_fail(self, mock_popen):
        mock_popen.return_value.communicate.return_value = ("", "")

        self.m._snapshot_from_vmx = mock.MagicMock(return_value="snapshot")
        self.m._is_running = mock.MagicMock(return_value=False)
        self.m._revert = mock.MagicMock()
        mock_popen.side_effect = OSError("tosti42")

        with pytest.raises(CuckooMachineError):
            self.m.start("/vmx/vm1.vmx", TestVMWare.task(), revert=True)

        self.m._revert.assert_called_once_with("/vmx/vm1.vmx", "snapshot")
        mock_popen.assert_called_once_with(
            [self.m.options.vmware.path, "start", "/vmx/vm1.vmx",
             self.m.options.vmware.mode], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.Popen")
    def test_start_non_revert(self, mock_popen):
        mock_popen.return_value.communicate.return_value = ("", "")

        self.m._snapshot_from_vmx = mock.MagicMock(return_value="snapshot")
        self.m._is_running = mock.MagicMock(return_value=False)
        self.m._revert = mock.MagicMock()

        self.m.start("/vmx/vm1.vmx", TestVMWare.task(), revert=False)

        self.m._revert.assert_not_called()
        mock_popen.assert_called_once_with(
            [self.m.options.vmware.path, "start", "/vmx/vm1.vmx",
             self.m.options.vmware.mode], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_stop(self, mock_call):
        self.m._is_running = mock.MagicMock(return_value=True)
        self.m._safe_stop = mock.MagicMock(return_value=True)

        mock_call.return_value = 0
        vmx_path = "/vmx/vm1.vmx"
        self.m.stop(vmx_path, safe=False)

        self.m._is_running.assert_called_once_with(vmx_path)
        self.m._safe_stop.assert_not_called()
        mock_call.assert_called_once_with(
            [self.m.options.vmware.path, "stop", vmx_path, "hard"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_stop_fail(self, mock_call):
        self.m._is_running = mock.MagicMock(return_value=True)
        self.m._safe_stop = mock.MagicMock(return_value=True)

        mock_call.return_value = 1
        vmx_path = "/vmx/vm1.vmx"

        with pytest.raises(CuckooMachineError):
            self.m.stop(vmx_path, safe=False)

        self.m._is_running.assert_called_once_with(vmx_path)
        self.m._safe_stop.assert_not_called()

        mock_call.assert_called_once_with(
            [self.m.options.vmware.path, "stop", vmx_path, "hard"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_stop_safe(self, mock_call):
        self.m._is_running = mock.MagicMock(return_value=True)
        self.m._safe_stop = mock.MagicMock(return_value=True)

        vmx_path = "/vmx/vm1.vmx"
        self.m.stop(vmx_path, safe=True)

        self.m._is_running.assert_called_once_with(vmx_path)
        self.m._safe_stop.assert_called_once_with(vmx_path)
        mock_call.assert_not_called()

    @mock.patch("cuckoo.machinery.vmware.subprocess.Popen")
    def test_safe_stop(self, mock_popen):
        self.m._is_running = mock.MagicMock(return_value=False)
        mock_popen.return_value.poll.return_value = 0
        mock_popen.return_value.returncode = 0

        ret = self.m._safe_stop("/vmx/vm1.vmx")

        mock_popen.assert_called_once_with(
            [self.m.options.vmware.path, "stop", "/vmx/vm1.vmx", "soft"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        assert ret == True

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_revert(self, mock_call):
        mock_call.return_value = 0

        self.m._revert("/vmx/vm1.vmx", "snapshot1")

        mock_call.assert_called_once_with(
            [self.m.options.vmware.path, "revertToSnapshot", "/vmx/vm1.vmx",
             "snapshot1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_revert_fail(self, mock_call):
        mock_call.return_value = 1

        with pytest.raises(CuckooMachineError):
            self.m._revert("/vmx/vm1.vmx", "snapshot1")

        mock_call.assert_called_once_with(
            [self.m.options.vmware.path, "revertToSnapshot", "/vmx/vm1.vmx",
             "snapshot1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    @mock.patch("cuckoo.machinery.vmware.subprocess.call")
    def test_revert_fail_oserr(self, mock_call):
        mock_call.return_value = 1
        mock_call.side_effect = OSError("Tosti42")

        with pytest.raises(CuckooMachineError):
            self.m._revert("/vmx/vm1.vmx", "snapshot1")

        mock_call.assert_called_once_with(
            [self.m.options.vmware.path, "revertToSnapshot", "/vmx/vm1.vmx",
             "snapshot1"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

class TestLibVirtMachinery(object):
    class task(object):
        def __init__(self):
            self.id = 1

    class machine(object):
        def __init__(self):
            self.label = "machine1"
            self.name = "machine1"
            self.snapshot = "snapshot1"

    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()
        abstracts.HAVE_LIBVIRT = True

        with mock.patch("cuckoo.common.abstracts.Database") as db:
            db.return_value = mock.MagicMock()
            self.m = abstracts.LibVirtMachinery()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("kvm"))

        self.m.vms = {}
        self.machineobj = TestLibVirtMachinery.machine()
        self.taskobj = TestLibVirtMachinery.task()

    def test_stop(self):
        """Test stopping of a running machine"""
        vm_mock = mock.MagicMock()
        vm_mock.isActive.return_value = True
        self.m.vms = {self.machineobj.label: vm_mock}
        self.m._status = mock.MagicMock(return_value=self.m.RUNNING)
        self.m._connect = mock.MagicMock(return_value="conn")
        self.m._wait_status = mock.MagicMock()
        self.m._disconnect = mock.MagicMock()

        self.m.stop(self.machineobj.label, safe=False)

        self.m._status.assert_called_once()
        self.m._connect.assert_called_once()
        self.m.vms[self.machineobj.label].isActive.assert_called_once()
        self.m.vms[self.machineobj.label].destroy.assert_called_once()
        self.m._disconnect.assert_called_once_with("conn")
        self.m._wait_status.assert_called_once_with(self.machineobj.label,
                                                    self.m.POWEROFF)

    def test_start(self):
        """Test revert to snapshot and starting a stopped
        machine"""
        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m._connect = mock.MagicMock(return_value="conn")
        self.m.db.view_machine_by_label = mock.MagicMock(
            return_value=self.machineobj
        )
        self.m._disconnect = mock.MagicMock()
        self.m._wait_status = mock.MagicMock()

        vm_mock = mock.MagicMock()
        vm_mock.snapshotListNames.return_value = [self.machineobj.snapshot]
        vm_mock.snapshotLookupByName.return_value = self.machineobj.snapshot
        self.m.vms = {self.machineobj.label: vm_mock}

        self.m.start(self.machineobj.label, self.taskobj, revert=True)

        self.m._status.assert_called_once_with(self.machineobj.label)
        self.m._connect.assert_called_once()
        self.m.db.view_machine_by_label.assert_called_once_with(
            self.machineobj.label
        )
        self.m.vms[self.machineobj.label]. \
            snapshotListNames.assert_called_once_with(flags=0)

        # Create should not be called because it is being
        # reverted to a snapshot
        self.m.vms[self.machineobj.label].create.assert_not_called()

        self.m.vms[self.machineobj.label]. \
            snapshotLookupByName.assert_called_once_with(
            self.machineobj.snapshot, flags=0
        )
        self.m.vms[self.machineobj.label]. \
            revertToSnapshot.assert_called_once_with(
            self.machineobj.snapshot, flags=0
        )
        self.m._disconnect.assert_called_once_with("conn")
        self.m._wait_status.assert_called_once_with(self.machineobj.label,
                                                    self.m.RUNNING)

    def test_start_non_revert(self):
        """Test starting a stopped machine without reverting
        to a snapshot"""
        self.m._status = mock.MagicMock(return_value=self.m.POWEROFF)
        self.m._connect = mock.MagicMock(return_value="conn")
        self.m.db.view_machine_by_label = mock.MagicMock(
            return_value=self.machineobj
        )
        self.m._disconnect = mock.MagicMock()
        self.m._wait_status = mock.MagicMock()

        vm_mock = mock.MagicMock()
        self.m.vms = {self.machineobj.label: vm_mock}

        self.m.start(self.machineobj.label, self.taskobj, revert=False)

        self.m._status.assert_called_once_with(self.machineobj.label)
        self.m._connect.assert_called_once()
        self.m.db.view_machine_by_label.assert_called_once_with(
            self.machineobj.label
        )
        self.m.vms[self.machineobj.label]. \
            snapshotListNames.assert_called_once_with(flags=0)

        # Create should be called because it is not being reverted back to a
        # snapshot
        self.m.vms[self.machineobj.label].create.assert_called_once()

        self.m.vms[self.machineobj.label]. \
            snapshotLookupByName.assert_not_called()
        self.m.vms[self.machineobj.label]. \
            revertToSnapshot.assert_not_called()

        self.m._disconnect.assert_called_once_with("conn")
        self.m._wait_status.assert_called_once_with(self.machineobj.label,
                                                    self.m.RUNNING)

class TestXenServer(object):
    class task(object):
        def __init__(self):
            self.id = 1

    class machine(object):
        def __init__(self):
            self.label = "machine1"
            self.name = "machine1"
            self.snapshot = "snapshot1"

    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()
        xenserver.HAVE_XENAPI = True
        xenserver.XenAPI = mock.MagicMock()

        with mock.patch("cuckoo.common.abstracts.Database") as db:
            db.return_value = mock.MagicMock()
            self.m = xenserver.XenServer()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("xenserver"))

        self.m.vms = {}
        self.machineobj = TestXenServer.machine()
        self.taskobj = TestXenServer.task()

    @mock.patch("cuckoo.machinery.xenserver.XenServer.session")
    def test_start(self, mock_ses):
        """Test restoring a snapshot and resuming the machine"""
        self.m._get_vm_ref = mock.MagicMock(return_value="vmref")
        self.m._get_vm_record = mock.MagicMock(return_value="vmrecord")
        self.m._is_halted = mock.MagicMock(return_value=True)
        self.m._snapshot_from_vm_uuid = mock.MagicMock(
            return_value="snapshot1"
        )

        self.m.start(self.machineobj.label, self.taskobj, revert=True)

        self.m._is_halted.assert_called_once_with("vmrecord")
        assert self.m._get_vm_ref.call_count == 2
        self.m._get_vm_record.assert_called_once_with("vmref")
        self.m._snapshot_from_vm_uuid.assert_called_once_with(
            self.machineobj.label
        )
        self.m.session.xenapi.VM.revert.assert_called_once_with("vmref")
        self.m.session.xenapi.VM.resume.assert_called_once_with(
            "vmref", False, False
        )

    @mock.patch("cuckoo.machinery.xenserver.XenServer.session")
    def test_start_non_revert(self, mock_ses):
        """Test starting a machine without restoring a snapshot"""
        self.m._get_vm_ref = mock.MagicMock(return_value="vmref")
        self.m._get_vm_record = mock.MagicMock(return_value="vmrecord")
        self.m._is_halted = mock.MagicMock(return_value=True)
        self.m._snapshot_from_vm_uuid = mock.MagicMock(
            return_value="snapshot1"
        )

        self.m.start(self.machineobj.label, self.taskobj, revert=False)

        self.m._is_halted.assert_called_once_with("vmrecord")
        self.m._get_vm_ref.assert_called_once()
        self.m._get_vm_record.assert_called_once_with("vmref")
        self.m._snapshot_from_vm_uuid.assert_called_once_with(
            self.machineobj.label
        )
        self.m.session.xenapi.VM.revert.assert_not_called()
        self.m.session.xenapi.VM.resume.assert_not_called()
        self.m.session.xenapi.VM.start.assert_called_once_with("vmref", False,
                                                               False)

    @mock.patch("cuckoo.machinery.xenserver.XenServer.session")
    def test_stop(self, mock_ses):
        """Test stopping a machine"""
        self.m._get_vm_ref = mock.MagicMock(return_value="vmref")
        self.m._get_vm_record = mock.MagicMock(return_value="vmrecord")
        self.m._is_halted = mock.MagicMock(return_value=False)

        self.m.stop(self.machineobj.label, safe=False)

        self.m._is_halted.assert_called_once_with("vmrecord")
        self.m._get_vm_ref.assert_called_once_with(self.machineobj.label)
        self.m._get_vm_record.assert_called_once_with("vmref")
        self.m.session.xenapi.VM.hard.shutdown("vmref")

class TestvSphere(object):
    class task(object):
        def __init__(self):
            self.id = 1

    class machine(object):
        def __init__(self):
            self.label = "machine1"
            self.name = "machine1"
            self.snapshot = "snapshot1"

    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()
        vsphere.HAVE_PYVMOMI = True
        vsphere.SmartConnection = mock.MagicMock()

        with mock.patch("cuckoo.common.abstracts.Database") as db:
            db.return_value = mock.MagicMock()
            self.m = vsphere.vSphere()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("vsphere"))

        self.machineobj = TestvSphere.machine()
        self.taskobj = TestvSphere.task()
        self.m.connect_opts = {}

    def test_stop(self):
        """Test stopping a machine"""
        self.m._get_virtual_machine_by_label = mock.MagicMock(
            return_value="vm"
        )
        self.m._stop_virtual_machine = mock.MagicMock()

        self.m.stop(self.machineobj.label, safe=False)
        self.m._get_virtual_machine_by_label.assert_called_once_with(
            mock.ANY, self.machineobj.label
        )
        self.m._stop_virtual_machine.assert_called_once_with("vm")

    def test_start(self):
        """Test reverting machine to snapshot and starting machine"""
        self.m.db.view_machine_by_label = mock.MagicMock(
            return_value=self.machineobj
        )
        self.m._get_virtual_machine_by_label = mock.MagicMock(
            return_value="vm"
        )
        self.m._revert_snapshot = mock.MagicMock()
        self.m._start_virtual_machine = mock.MagicMock()

        self.m.start(self.machineobj.label, self.taskobj, revert=True)

        self.m.db.view_machine_by_label.assert_called_once_with(
            self.machineobj.label
        )
        self.m._get_virtual_machine_by_label.assert_called_once_with(
            mock.ANY, self.machineobj.label
        )
        self.m._revert_snapshot.assert_called_once_with(
            "vm", self.machineobj.snapshot
        )
        self.m._start_virtual_machine.assert_not_called()

    def test_start_non_revert(self):
        """Test starting machine without reverting snapshot"""
        self.m.db.view_machine_by_label = mock.MagicMock(
            return_value=self.machineobj
        )
        self.m._get_virtual_machine_by_label = mock.MagicMock(
            return_value="vm"
        )
        self.m._revert_snapshot = mock.MagicMock()
        self.m._start_virtual_machine = mock.MagicMock()

        self.m.start(self.machineobj.label, self.taskobj, revert=False)

        self.m.db.view_machine_by_label.assert_called_once_with(
            self.machineobj.label
        )
        self.m._get_virtual_machine_by_label.assert_called_once_with(
            mock.ANY, self.machineobj.label
        )
        self.m._revert_snapshot.assert_not_called()
        self.m._start_virtual_machine.assert_called_once_with("vm")
