# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
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
        os_path_exists.assert_called_with("/home/cuckoo/images/snapshot_ubuntu32.qcow2")
        os_remove.assert_called_with("/home/cuckoo/images/snapshot_ubuntu32.qcow2")