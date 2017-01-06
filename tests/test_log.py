# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import mock
import tempfile

from cuckoo.core.log import logger, init_logger
from cuckoo.core.startup import init_logging
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd

def test_init_logging():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logging(logging.DEBUG)

def test_logger():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logger(logging.getLogger(), "cuckoo.json")

    with mock.patch("time.time") as p:
        p.return_value = 123456
        logger("cuckoo.json", "test %s", "message", action="a", status="b")

    assert json.load(open(cwd("log", "cuckoo.json"), "rb")) == {
        "action": "a",
        "level": "info",
        "message": "test message",
        "status": "b",
        "task_id": None,
        "time": 123456,
    }
