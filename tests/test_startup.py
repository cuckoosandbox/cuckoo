# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import tempfile

from cuckoo.core.startup import init_modules
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, load_signatures

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
