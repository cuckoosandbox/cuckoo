# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile

from cuckoo.common.virustotal import VirusTotalAPI
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd

def test_vt_init():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "processing": {
            "virustotal": {
                "key": "hello",
                "timeout": 32,
                "scan": False,
            },
        },
    })
    v = VirusTotalAPI()
    assert v.apikey == "hello"
    assert v.timeout == 32
    assert v.scan is False
