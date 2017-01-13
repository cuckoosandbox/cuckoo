# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import mock
import tempfile

from cuckoo.core.log import logger, tz
from cuckoo.core.startup import init_logging, init_logfile
from cuckoo.main import cuckoo_create, main
from cuckoo.misc import set_cwd, cwd

def test_init_logging():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logging(logging.DEBUG)

def test_logger():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logfile("cuckoo.json")

    with mock.patch("time.time") as p:
        p.return_value = 1484232001
        logger("cuckoo.json", "test %s", "message", action="a", status="b")

    assert json.load(open(cwd("log", "cuckoo.json"), "rb")) == {
        "asctime": mock.ANY,
        "action": "a",
        "level": "info",
        "message": "test message",
        "status": "b",
        "task_id": None,
        "time": 1484232001,
    }

def test_logging():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logfile("cuckoo.json")

    with mock.patch("time.time") as p:
        p.return_value = 1484232002
        log = logging.getLogger("test.module")
        log.warning("test %s", "message2", extra={
            "action": "a", "status": "b",
        })

    assert json.load(open(cwd("log", "cuckoo.json"), "rb")) == {
        "asctime": mock.ANY,
        "action": "a",
        "level": "warning",
        "message": "test message2",
        "status": "b",
        "task_id": None,
        "time": 1484232002,
    }

def test_process_json_logging():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    init_logfile("process-p0.json")

    def process_tasks(instance, maxcount):
        logger(
            "process-p0.json", "foo bar",
            action="hello.world", status="success"
        )

    with mock.patch("cuckoo.main.Database") as p0:
        with mock.patch("cuckoo.main.process_tasks") as p1:
            with mock.patch("time.time") as p2:
                p1.side_effect = process_tasks
                p2.return_value = 1484232003
                main.main(
                    ("--cwd", cwd(), "process", "p0"), standalone_mode=False
                )

    assert json.load(open(cwd("log", "process-p0.json"), "rb")) == {
        "asctime": mock.ANY,
        "action": "hello.world",
        "level": "info",
        "message": "foo bar",
        "status": "success",
        "task_id": None,
        "time": 1484232003,
    }
