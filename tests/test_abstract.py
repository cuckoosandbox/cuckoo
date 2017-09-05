# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import tempfile

from cuckoo.common import abstracts
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.objects import Dictionary
from cuckoo.core.database import Database
from cuckoo.misc import cwd, set_cwd

class TestProcessing:
    def setup(self):
        self.p = abstracts.Processing()

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.p.run()

class TestReport:
    def setup(self):
        self.r = abstracts.Report()

    def test_set_path(self):
        dir = tempfile.mkdtemp()
        rep_dir = os.path.join(dir, "reports")
        self.r.set_path(dir)
        assert os.path.exists(rep_dir)
        os.rmdir(rep_dir)

    def test_options_none(self):
        assert self.r.options is None

    def test_set_options_assignment(self):
        foo = {1: 2}
        self.r.set_options(foo)
        assert foo == self.r.options

    def test_not_implemented_run(self):
        with pytest.raises(NotImplementedError):
            self.r.run({})

class TestMachinery:

    def setup_class(self):
        self.tmp = tempfile.mkdtemp()
        set_cwd(self.tmp)
        Database().connect(dsn="sqlite:///:memory:")
        self.m = abstracts.Machinery()

    def test_set_options(self):
        options = Dictionary({"no": "yes"})
        self.m.set_options(options)

        assert self.m.options == options
        print(self.m.options)

    def test_initialize(self):
        self.m.set_options(Dictionary({
            "virtualbox":  {
                "machines": ["test_machine_vm1"]
            },
            "interface": "vboxnet0",
            "test_machine_vm1": Dictionary({
                "label": "test_machine_vm1",
                "resultserver_ip": "192.168.56.1",
                "resultserver_port": 2042,
                "ip": "192.168.56.101",
                "tags": "tag1,tag2",
                "snapshot": None,
                "rdp_port": "",
                "locked_by": None,
                "platform": "windows"
             })
        }
        ))

        self.m.initialize("virtualbox")
        res = self.m.db.view_machine(name="test_machine_vm1")

        assert res.name == "test_machine_vm1"

    def test_pcap_path(self):
        pcap_path = self.m.pcap_path(42)
        path = os.path.join(self.tmp, "storage", "analyses", "42", "dump.pcap")

        assert pcap_path == path

    def test_machines(self):
        machine1 = self.m.db.view_machine("test_machine_vm1")
        assert self.m.machines()[0].name == machine1.name

    def test_availables(self):
        self.m.db.lock_machine(locked_by=42)
        count_locked_by = self.m.availables(locked_by=42)
        count_unlocked1 = self.m.availables()
        self.m.db.unlock_machine(locked_by=42)
        count_unlocked2 = self.m.availables()

        assert count_locked_by == 1
        assert count_unlocked1 == 0
        assert count_unlocked2 == 1

    def test_acquire(self):
        vm_name = "test_machine_vm1"
        machine_id = self.m.acquire(machine_id=vm_name)
        self.m.db.unlock_machine(label=vm_name)
        machine_plat = self.m.acquire(platform="windows")
        self.m.db.unlock_machine(label=vm_name)
        machine_tags_exp = self.m.acquire(tags=["tag1", "tag2"], locked_by=42)
        self.m.db.unlock_machine(label=vm_name)

        with pytest.raises(CuckooOperationalError):
            self.m.acquire(platform="DogeOSv1400")
        with pytest.raises(CuckooOperationalError):
            self.m.acquire(machine_id="JYtrvUIYNm")
        with pytest.raises(CuckooOperationalError):
            self.m.acquire(tags=["ErrorTag"])

        assert machine_id.label == vm_name and machine_id.locked
        assert machine_plat.platform == "windows" and machine_plat.locked
        assert machine_tags_exp.locked_by == 42 and machine_tags_exp.locked

    def test_release(self):
        m1 = self.m.db.lock_machine("test_machine_vm1")
        self.m.release("test_machine_vm1")
        m2 = self.m.db.view_machine("test_machine_vm1")

        assert m1.locked
        assert not m2.locked

    def test_running(self):
        self.m.db.set_machine_status("test_machine_vm1", "running")
        assert self.m.running()[0].name == "test_machine_vm1"

    def test_shutdown(self):
        with pytest.raises(NotImplementedError,
                           message="Should find 1 running vm"
                                               " and raise exception"):
            self.m.shutdown()

    def test_set_status(self):
        self.m.set_status("test_machine_vm1", "poweroff")
        m = self.m.db.view_machine("test_machine_vm1")
        assert m.status == "poweroff"

    def test_start(self):
        with pytest.raises(NotImplementedError):
            self.m.start("test_machine_vm1", task=None, revert=True)

    def test_stop(self):
        with pytest.raises(NotImplementedError):
            self.m.stop("test_machine_vm1", safe=True)

    def test_list(self):
        with pytest.raises(NotImplementedError):
            self.m._list()

    def test_dump_memory(self):
        with pytest.raises(NotImplementedError):
            self.m.dump_memory("test_machine_vm1", cwd("storage", "analyses",
                                                       "42"))
    def test_status(self):
        with pytest.raises(NotImplementedError):
            self.m._status("test_machine_w1")

    def test_wait_status(self):
        with pytest.raises(NotImplementedError):
            self.m._wait_status("test_machine_w1", ["poweroff", "running"])
