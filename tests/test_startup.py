# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import tempfile

from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, load_signatures, cwd
from cuckoo.core.startup import init_modules, init_yara

@mock.patch("cuckoo.core.startup.log")
def test_init_modules(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    load_signatures()

    logs = []

    def log(fmt, *args):
        logs.append(fmt % args if args else fmt)

    p.debug.side_effect = log

    init_modules()

    logs = "\n".join(logs)
    assert "KVM" in logs
    assert "Xen" in logs
    assert "CreatesExe" in logs
    assert "SystemMetrics" in logs

def test_init_yara():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    def count(dirpath):
        ret = 0
        for name in os.listdir(dirpath):
            if name.endswith((".yar", ".yara")):
                ret += 1
        return ret

    # Will change when we start shipping more Yara rules by default.
    assert count(cwd("yara", "binaries")) == 3
    assert not count(cwd("yara", "urls"))
    assert not count(cwd("yara", "memory"))

    init_yara()

    assert os.path.exists(cwd("yara", "index_binaries.yar"))
    assert not os.path.exists(cwd("yara", "index_urls.yar"))
    assert not os.path.exists(cwd("yara", "index_memory.yar"))

    buf = open(cwd("yara", "index_binaries.yar"), "rb").read().split("\n")
    assert 'include "%s"' % cwd("yara", "binaries", "embedded.yar") in buf
