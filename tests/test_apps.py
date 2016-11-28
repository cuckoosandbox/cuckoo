# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import tempfile

from cuckoo.common.files import Files
from cuckoo.main import main
from cuckoo.misc import set_cwd, cwd

def test_init():
    set_cwd(tempfile.mkdtemp())
    with pytest.raises(SystemExit):
        main.main(
            ("--cwd", cwd(), "--nolog", "init"),
            standalone_mode=False
        )

class TestAppsWithCWD(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        Files.create(cwd(), ".cwd", "A"*40)

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

    def test_process(self):
        with mock.patch("cuckoo.main.process_task") as p:
            p.return_value = None
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

        with mock.patch("cuckoo.main.process_tasks") as p:
            p.return_value = None
            main.main(
                ("--cwd", cwd(), "process", "instance"),
                standalone_mode=False
            )
            p.assert_called_once_with("instance", 0)

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
            p.assert_called_once_with(dirpath, False, None)

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
