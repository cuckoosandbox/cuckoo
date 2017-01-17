# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import mock
import os
import pytest
import tempfile

from cuckoo.apps.apps import process, process_task
from cuckoo.apps.migrate import import_legacy_analyses
from cuckoo.common.files import Files
from cuckoo.core.log import logger
from cuckoo.core.startup import init_logfile, init_console_logging
from cuckoo.main import main, cuckoo_create
from cuckoo.misc import set_cwd, cwd, mkdir, is_windows

@mock.patch("cuckoo.main.load_signatures")
def test_init(p):
    set_cwd(tempfile.mkdtemp())
    with pytest.raises(SystemExit):
        main.main(
            ("--cwd", cwd(), "--nolog", "init"),
            standalone_mode=False
        )
    p.assert_not_called()

def init_legacy_analyses():
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    dirpath = tempfile.mkdtemp()
    mkdir(dirpath, "storage")
    mkdir(dirpath, "storage", "analyses")

    mkdir(dirpath, "storage", "analyses", "1")
    mkdir(dirpath, "storage", "analyses", "1", "logs")
    Files.create(
        (dirpath, "storage", "analyses", "1", "logs"), "a.txt", "a"
    )
    mkdir(dirpath, "storage", "analyses", "1", "reports")
    Files.create(
        (dirpath, "storage", "analyses", "1", "reports"), "b.txt", "b"
    )

    mkdir(dirpath, "storage", "analyses", "2")
    Files.create((dirpath, "storage", "analyses", "2"), "cuckoo.log", "log")

    Files.create((dirpath, "storage", "analyses"), "latest", "last!!1")
    return dirpath

def test_import_legacy_analyses():
    with pytest.raises(RuntimeError) as e:
        import_legacy_analyses(None, mode="notamode")
    e.match("mode should be either")

    dirpath = init_legacy_analyses()
    assert sorted(import_legacy_analyses(dirpath, mode="copy")) == [1, 2]
    assert open(cwd("logs", "a.txt", analysis=1), "rb").read() == "a"
    assert open(cwd("reports", "b.txt", analysis=1), "rb").read() == "b"
    assert open(cwd("cuckoo.log", analysis=2), "rb").read() == "log"
    assert not os.path.exists(cwd(analysis="latest"))

    if not is_windows():
        assert not os.path.islink(cwd(analysis=1))
        assert not os.path.islink(cwd(analysis=2))

    dirpath = init_legacy_analyses()
    assert sorted(import_legacy_analyses(dirpath, mode="symlink")) == [1, 2]
    assert open(cwd("logs", "a.txt", analysis=1), "rb").read() == "a"
    assert open(cwd("reports", "b.txt", analysis=1), "rb").read() == "b"
    assert open(cwd("cuckoo.log", analysis=2), "rb").read() == "log"
    assert not os.path.exists(cwd(analysis="latest"))

    if not is_windows():
        assert os.path.islink(cwd(analysis=1))
        assert os.path.islink(cwd(analysis=2))

class TestAppsWithCWD(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

    @mock.patch("cuckoo.main.load_signatures")
    @mock.patch("cuckoo.main.cuckoo_main")
    def test_main(self, p, q):
        p.side_effect = SystemExit(0)
        main.main(("--cwd", cwd(), "-d", "--nolog"), standalone_mode=False)
        q.assert_called_once()

    def test_api(self):
        with mock.patch("cuckoo.main.cuckoo_api") as p:
            p.return_value = None
            main.main(("--cwd", cwd(), "api"), standalone_mode=False)
            p.assert_called_once_with("localhost", 8090, False)

    def test_community(self):
        with mock.patch("cuckoo.main.fetch_community") as p:
            p.return_value = None
            main.main(("--cwd", cwd(), "community"), standalone_mode=False)
            p.assert_called_once_with(
                force=False, branch="master", filepath=None
            )

    def test_clean(self):
        with mock.patch("cuckoo.main.cuckoo_clean") as p:
            p.return_value = None
            main.main(("--cwd", cwd(), "clean"), standalone_mode=False)
            p.assert_called_once_with()

    def test_submit(self):
        with mock.patch("cuckoo.main.submit_tasks") as p:
            p.return_value = []
            main.main((
                "--cwd", cwd(), "submit", Files.create(cwd(), "a.txt", "hello")
            ), standalone_mode=False)

    @mock.patch("cuckoo.main.load_signatures")
    @mock.patch("cuckoo.main.process_task")
    def test_process_once(self, p, q):
        main.main(
            ("--cwd", cwd(), "process", "-r", "1234"),
            standalone_mode=False
        )
        p.assert_called_once_with({
            "id": 1234,
            "category": "file",
            "target": "",
            "options": "",
        })
        q.assert_called_once()

    @mock.patch("cuckoo.main.load_signatures")
    @mock.patch("cuckoo.main.process_tasks")
    def test_process_many(self, p, q):
        main.main(
            ("--cwd", cwd(), "process", "instance"),
            standalone_mode=False
        )
        p.assert_called_once_with("instance", 0)
        q.assert_called_once()

    def test_dnsserve(self):
        with mock.patch("cuckoo.main.cuckoo_dnsserve") as p:
            p.return_value = None
            main.main(("--cwd", cwd(), "dnsserve"), standalone_mode=False)
            p.assert_called_once_with("0.0.0.0", 53, None, None)

    def test_web(self):
        curdir = os.getcwd()

        s = "django.core.management.execute_from_command_line"
        with mock.patch(s) as p:
            p.return_value = None
            main.main(("--cwd", cwd(), "web"), standalone_mode=False)
            p.assert_called_once_with(
                ("cuckoo", "runserver", "localhost:8000")
            )

        with mock.patch(s) as p:
            p.return_value = None
            main.main(
                ("--cwd", cwd(), "web", "foo", "bar"),
                standalone_mode=False
            )
            p.assert_called_once_with(("cuckoo", "foo", "bar"))

        os.chdir(curdir)

    def test_machine(self):
        with mock.patch("cuckoo.main.cuckoo_machine") as p:
            p.return_value = None
            main.main((
                "--cwd", cwd(), "machine", "machine", "1.2.3.4", "--add"
            ), standalone_mode=False)

            p.assert_called_once_with(
                "machine", True, False, "1.2.3.4", "windows",
                None, None, None, None, None
            )

    def test_import(self):
        with mock.patch("cuckoo.main.import_cuckoo") as p:
            p.return_value = None
            dirpath = tempfile.mkdtemp()
            main.main(
                ("--cwd", cwd(), "import", dirpath),
                standalone_mode=False
            )
            p.assert_called_once_with(None, dirpath, False, None)

    def test_dist_server(self):
        with mock.patch("cuckoo.main.cuckoo_distributed") as p:
            p.return_value = None
            main.main(
                ("--cwd", cwd(), "distributed", "server"),
                standalone_mode=False
            )
            p.assert_called_once_with("localhost", 9003, False)

    def test_dist_instance(self):
        with mock.patch("cuckoo.main.cuckoo_distributed_instance") as p:
            p.return_value = None
            main.main(
                ("--cwd", cwd(), "distributed", "instance", "name"),
                standalone_mode=False
            )
            p.assert_called_once_with("name")

    def test_dist_migrate(self):
        with mock.patch("cuckoo.main.subprocess.check_call") as p:
            p.return_value = None
            main.main(
                ("--cwd", cwd(), "distributed", "migrate"),
                standalone_mode=False
            )
            p.assert_called_once_with(
                ["alembic", "-x", "cwd=%s" % cwd(), "upgrade", "head"],
                cwd=cwd("distributed", "migration", private=True)
            )

@mock.patch("cuckoo.apps.apps.RunProcessing")
@mock.patch("cuckoo.apps.apps.RunSignatures")
@mock.patch("cuckoo.apps.apps.RunReporting")
def test_process_nodelete(r, s, p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "delete_original": False,
                "delete_bin_copy": False,
            },
        },
    })

    filepath1 = Files.temp_put("hello world")
    filepath2 = Files.create(cwd("storage", "binaries"), "A"*40, "binary")

    process(filepath1, filepath2, 1)
    assert os.path.exists(filepath1)
    assert os.path.exists(filepath2)

@mock.patch("cuckoo.apps.apps.RunProcessing")
@mock.patch("cuckoo.apps.apps.RunSignatures")
@mock.patch("cuckoo.apps.apps.RunReporting")
def test_process_dodelete(r, s, p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create(cfg={
        "cuckoo": {
            "cuckoo": {
                "delete_original": True,
                "delete_bin_copy": True,
            },
        },
    })

    filepath1 = Files.temp_put("hello world")
    filepath2 = Files.create(cwd("storage", "binaries"), "A"*40, "binary")

    process(filepath1, filepath2, 1)
    assert not os.path.exists(filepath1)
    assert not os.path.exists(filepath2)

@mock.patch("cuckoo.apps.apps.process")
@mock.patch("cuckoo.apps.apps.Database")
def test_process_log_taskid(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    init_console_logging(logging.DEBUG)
    init_logfile("process-p0.json")

    def log_something(target, copy_path, task):
        logger("test message", action="hello.world", status="success")

    q.side_effect = log_something
    process_task({
        "id": 12345,
        "category": "url",
        "target": "http://google.com/",
        "package": "ie",
        "options": {},
    })

    for line in open(cwd("log", "process-p0.json"), "rb"):
        obj = json.loads(line)
        if obj["action"] == "hello.world":
            assert obj["task_id"] == 12345
            break
    else:
        raise
