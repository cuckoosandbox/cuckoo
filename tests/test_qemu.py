# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import tempfile

from cuckoo.common.config import Config
from cuckoo.common.files import Folders
from cuckoo.common.objects import Dictionary
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.machinery.qemu import QEMU
from cuckoo.misc import set_cwd, cwd

class TestQemu(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Folders.create(cwd(), "conf")
        write_cuckoo_conf()

        with mock.patch("cuckoo.common.abstracts.Database") as p:
            p.return_value = mock.MagicMock()
            self.m = QEMU()

        self.m.db.clean_machines.assert_called_once()
        self.m.set_options(Config("qemu"))

    @mock.patch("cuckoo.machinery.qemu.os.remove")
    @mock.patch("cuckoo.machinery.qemu.os.path.exists")
    def test_snapshot_filename(self, os_path_exists, os_remove):
        class named_machine(object):
            name = "ubuntu32"

        self.m.db.view_machine_by_label.return_value = named_machine()
        self.m.set_options(Dictionary({
            "ubuntu32": Dictionary({
                "image": "/home/cuckoo/images/ubuntu32.qcow2"
            })
        }))

        with pytest.raises(AttributeError) as e:
            self.m.start("label", None)

        e.match("no attribute 'qemu_img'")

        snapshot_path = os.path.join("/home/cuckoo/images", "snapshot_ubuntu32.qcow2")
        os_path_exists.assert_called_with(snapshot_path)
        os_remove.assert_called_with(snapshot_path)

    @mock.patch("cuckoo.machinery.qemu.subprocess.Popen")
    def test_snapshot_config(self, subprocess_popen):
        class named_machine(object):
            name = "ubuntu32"

        self.m.db.view_machine_by_label.return_value = named_machine()
        self.m.set_options(Dictionary({
            "ubuntu32": Dictionary({
                "image": "/home/cuckoo/images/ubuntu32.qcow2",
                "arch": "x86",
                "snapshot": "booted"
            })
        }))

        self.m.start("label", None)
        assert subprocess_popen.call_count == 1
        assert all(x in subprocess_popen.call_args[0][0] for x in ("-loadvm", "booted"))

    def test_kvm_config(self):
        class named_machine(object):
            name = "ubuntu32"

        self.m.db.view_machine_by_label.return_value = named_machine()
        self.m.set_options(Dictionary({
            "ubuntu32": Dictionary({
                "image": "/home/cuckoo/images/ubuntu32.qcow2",
                "arch": "x86",
                "enable_kvm": True
            })
        }))

        self.m.qemu_img = mock.MagicMock()

        with mock.patch("cuckoo.machinery.qemu.subprocess.Popen") as subprocess_popen:
            proc = mock.MagicMock()
            proc.communicate.return_value = "", ""
            subprocess_popen.side_effect = proc, mock.MagicMock()

            self.m.start("label", None)

        assert subprocess_popen.call_count == 2
        assert "-enable-kvm" in subprocess_popen.call_args[0][0]
