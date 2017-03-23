# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import pytest
import tempfile

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.resultserver import ResultHandler, FileUpload
from cuckoo.core.startup import init_logging
from cuckoo.main import cuckoo_create
from cuckoo.misc import mkdir, set_cwd, cwd

@mock.patch("cuckoo.core.resultserver.select")
def test_open_process_log_unicode(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()
    mkdir(cwd(analysis=1))
    mkdir(cwd("logs", analysis=1))

    request = server = mock.MagicMock()

    class Handler(ResultHandler):
        storagepath = cwd(analysis=1)

        def handle(self):
            pass

    init_logging(logging.DEBUG)

    try:
        task_log_start(1)
        Handler(request, (None, None), server).open_process_log({
            "pid": 1, "ppid": 2, "process_name": u"\u202e", "track": True,
        })
    finally:
        task_log_stop(1)

class TestFileUpload(object):
    def fileupload(self, handler):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        mkdir(cwd(analysis=1))
        mkdir(cwd("logs", analysis=1))

        handler.storagepath = cwd(analysis=1)
        fu = FileUpload(handler, None)
        fu.init()
        for x in fu:
            pass
        fu.close()

    def test_success(self):
        class Handler(object):
            reads = [
                "this", "is", "a", "test", None
            ]

            def read_newline(self, strip):
                return "logs/1.log"

            def read_any(self):
                return self.reads.pop(0)

        self.fileupload(Handler())

        with open(cwd("logs", "1.log", analysis=1), "rb") as f:
            assert f.read() == "thisisatest"

    def invalid_path(self, path):
        class Handler(object):
            def read_newline(self, strip):
                return path

        with pytest.raises(CuckooOperationalError) as e:
            self.fileupload(Handler())
        e.match("banned path")

    def test_invalid_paths(self):
        self.invalid_path("/tmp/foobar")
        self.invalid_path("../hello")
        self.invalid_path("../../foobar")
