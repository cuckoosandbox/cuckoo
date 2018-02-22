# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import pytest
import subprocess
import tempfile

from cuckoo.common.config import config, Config
from cuckoo.common.exceptions import (
    CuckooMachineError, CuckooCriticalError, CuckooMachineSnapshotError,
    CuckooDependencyError, CuckooMissingMachineError
)
from cuckoo.common.files import Folders, Files
from cuckoo.common.objects import Dictionary
from cuckoo.core.database import Database
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.startup import init_logging
from cuckoo.machinery.esx import ESX
from cuckoo.machinery.virtualbox import VirtualBox
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

    def test_start_restore_oserror(self):
        class machine_no_snapshot(object):
            snapshot = None
            options = []

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

    def test_enable_vrde(self):
        self.m.enable_remote_control("label")
        assert self.m.remote_control is True

        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = "", ""
            p.return_value.returncode = 0
            self.m.enable_vrde("label")

        p.assert_has_calls([
            mock.call(
                ["/usr/bin/VBoxManage", "modifyvm", "label", "--vrde", "on"],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
            mock.call(
                ["/usr/bin/VBoxManage", "modifyvm", "label", "--vrdemulticon", "on"],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
            mock.call(
                ["/usr/bin/VBoxManage", "modifyvm", "label", "--vrdeport", "5000-5050"],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
            mock.call(
                ["/usr/bin/VBoxManage", "showvminfo", "label", "--machinereadable"],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
        ])

    def test_disable_remotecontrol(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = "", ""
            p.return_value.returncode = 0
            self.m.disable_remote_control("label")

        p.assert_has_calls([
            mock.call(
                ["/usr/bin/VBoxManage", "modifyvm", "label", "--vrde", "off"],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
        ])

    def test_get_remote_control_params(self):
        with mock.patch("cuckoo.machinery.virtualbox.Popen") as p:
            p.return_value.communicate.return_value = "vrdeport=5000", ""
            p.return_value.returncode = 0
            params = self.m.get_remote_control_params("label")

        p.assert_has_calls([
            mock.call(
                [
                    "/usr/bin/VBoxManage", "showvminfo",
                    "label", "--machinereadable",
                ],
                close_fds=True, stderr=-1, stdout=-1
            ),
            mock.call().communicate(),
        ])

        assert params == {
            "protocol": "rdp",
            "host": "127.0.0.1",
            "port": 5000,
        }

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
