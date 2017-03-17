# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path

from lib.api.dse import Capcom
from lib.core.driver import Driver

@mock.patch("os.path.exists")
@mock.patch("shutil.copy")
def test_copy_driver(p, q):
    d = Driver("foo", "bar")
    d.is_64bit = True
    d.copy_driver()

    q.assert_called_once_with("bin\\foo-x64.sys")
    sysroot = os.path.expandvars("%SystemRoot%")
    p.assert_called_once_with(
        "bin\\foo-x64.sys", "%s\\sysnative\\drivers\\bar.sys" % sysroot
    )

class TestCapcom(object):
    @mock.patch("platform.machine")
    def setup(self, p):
        p.return_value = "amd64"
        self.c = Capcom()

    def test_is64bit(self):
        # Ensure that the above works.
        assert self.c.is_64bit is True

    def test_primitives(self):
        sc = self.c.arch.get_MmGetSystemRoutineAddress().encode("hex")
        assert sc == "48890df1ffffffc3"

        sc = self.c.arch.read32(0x1122334455667788).encode("hex")
        assert sc == "48b88877665544332211488b00488905e4ffffffc3"

        sc = self.c.arch.write32(0x1122334455667788, 0x42424242).encode("hex")
        assert sc == "48b88877665544332211c70042424242c3"
