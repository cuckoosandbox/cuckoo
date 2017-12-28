# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path

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
