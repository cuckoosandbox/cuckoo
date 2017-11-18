# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import mock
import tempfile

from cuckoo.core.database import Database
from cuckoo.core.log import logger
from cuckoo.core.startup import (
    init_logging, init_logfile, init_console_logging, init_yara
)
from cuckoo.main import cuckoo_create, main
from cuckoo.misc import set_cwd, cwd

db = Database()

def reset_logging():
    """Resets the logging module to its initial state so that we can
    re-register all kinds of logging logic for unit testing purposes."""
    logging.root = logging.RootLogger(logging.WARNING)
    logging.Logger.root = logging.root
    logging.Logger.manager = logging.Manager(logging.Logger.root)

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
        logger("test %s", "message", action="a", status="b")

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
    init_yara()
    init_logfile("process-p0.json")

    def process_tasks(instance, maxcount):
        logger("foo bar", action="hello.world", status="success")

    with mock.patch("cuckoo.main.Database"):
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

def test_init_logging_info(capsys):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    reset_logging()
    init_console_logging(logging.WARNING)
    init_logging(logging.WARNING)

    log = logging.getLogger("testing")
    log.debug("debug test", extra={
        "action": "foo",
        "status": "bar",
    })
    log.info("info test", extra={
        "action": "foo",
        "status": "bar",
    })
    log.warning("warning test", extra={
        "action": "foo",
        "status": "bar",
    })

    buf = open(cwd("log", "cuckoo.log")).read()
    assert "debug test" not in buf
    assert "info test" not in buf
    assert "warning test" in buf

    buf = open(cwd("log", "cuckoo.json")).read()
    assert "debug test" in buf
    assert "info test" in buf
    assert "warning test" in buf

    _, buf = capsys.readouterr()
    assert "debug test" not in buf
    assert "info test" not in buf
    assert "warning test" in buf

def test_init_console_logging(capsys):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    reset_logging()
    init_console_logging(logging.DEBUG)

    log = logging.getLogger("console-testing")
    log.debug("this is a test")

    _, buf = capsys.readouterr()
    assert "console-testing" in buf
    assert "this is a test" in buf

def test_log_error_action():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    db.connect()

    reset_logging()
    init_console_logging(logging.DEBUG)

    task_id = db.add_path(__file__)
    assert db.view_errors(task_id) == []

    logging.getLogger(__name__).error("message1", extra={
        "error_action": "erroraction",
        "task_id": task_id,
    })

    logging.getLogger(__name__).error("message2", extra={
        "task_id": task_id,
    })

    errors = db.view_errors(task_id)
    assert len(errors) == 2
    assert errors[0].message == "message1"
    assert errors[0].action == "erroraction"
    assert errors[1].message == "message2"
    assert errors[1].action is None
