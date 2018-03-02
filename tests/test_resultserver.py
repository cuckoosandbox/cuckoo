# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import print_function

# Testing TODO:
# - Socket timeout, cleanup
# - Task cleanup
# - Invalid path tests
# - Double LOG command

import logging
import mock
import pytest
import tempfile
import shutil

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.resultserver import FileUpload, LogHandler, BsonStore
from cuckoo.core.startup import init_logging
from cuckoo.main import cuckoo_create
from cuckoo.misc import mkdir, set_cwd, cwd

# TODO: restore this test
'''
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
'''

@pytest.fixture(scope='module')
def cuckoo_cwd():
    """Create a temporary Cuckoo working directory"""
    path = tempfile.mkdtemp()
    print('Temporary path:', path)
    set_cwd(path)
    cuckoo_create()
    mkdir(cwd(analysis=1))
    yield path
    shutil.rmtree(path)


def mock_handler_context(klass, path, lines, data, version=None):
    class FakeContext:
        storagepath = path

        def read_newline(self):
            if not lines:
                raise EOFError
            return lines.pop(0)

        def read_any(self):
            if not data:
                raise EOFError
            return data.pop(0)

        def read(self, size):
            # TODO: we can test expected sizes here
            return self.read_any()

    h = klass(FakeContext(), version)
    h.init()
    h.handle()
    h.close()
    return h

@pytest.mark.usefixtures('cuckoo_cwd')
class TestFileUpload(object):
    def test_success(self):
        mock_handler_context(FileUpload,
                             cwd(analysis=1),
                             ['logs/1.log'],
                             ['this', 'is', 'a', 'test'])

        with open(cwd("logs", "1.log", analysis=1), "rb") as f:
            assert f.read() == "thisisatest"

    def invalid_path(self, path):
        with pytest.raises(CuckooOperationalError) as e:
            mock_handler_context(FileUpload, cwd(analysis=1), [path], [])
        e.match("banned path")

    def test_invalid_paths(self):
        self.invalid_path("/tmp/foobar")
        self.invalid_path("../hello")
        self.invalid_path("../../foobar")


@pytest.mark.usefixtures('cuckoo_cwd')
class TestLogHandler(object):
    def test_success(self):
        mock_handler_context(LogHandler,
                             cwd(analysis=1),
                             [],
                             ['first\n', 'second\n'])

        with open(cwd("analysis.log", analysis=1), "rb") as f:
            assert f.read() == "first\nsecond\n"


@pytest.mark.usefixtures('cuckoo_cwd')
class TestBsonStore(object):
    def test_success(self):
        mock_handler_context(BsonStore,
                             cwd(analysis=1),
                             [],
                             ['\x01\x00\x00\x00', 'a'],
                             1)

        with open(cwd("logs/1.bson", analysis=1), "rb") as f:
            assert f.read() == "\x01\x00\x00\x00a"
