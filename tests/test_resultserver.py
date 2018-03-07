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
import pytest
import tempfile
import shutil
import json

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.resultserver import RESULT_DIRECTORIES
from cuckoo.core.resultserver import FileUpload, LogHandler, BsonStore
from cuckoo.core.startup import init_logging
from cuckoo.main import cuckoo_create
from cuckoo.misc import mkdir, set_cwd, cwd


@pytest.fixture(scope='module')
def cuckoo_cwd():
    """Create a temporary Cuckoo working directory"""
    path = tempfile.mkdtemp()
    print('Temporary path:', path)
    set_cwd(path)
    cuckoo_create()
    anal_path = cwd(analysis=1)
    Folders.create(anal_path, RESULT_DIRECTORIES)
    yield path
    shutil.rmtree(path)


def mock_handler_context(klass, path, lines, data, version=None):
    class FakeContext:
        storagepath = path
        buf = ''
        task_id = 1

        def read_newline(self):
            if not lines:
                raise EOFError
            return lines.pop(0)

        def read(self, size=None):
            if not data:
                raise EOFError
            return data.pop(0)

        def copy_to_fd(self, fd, max_size=None):
            while True:
                try:
                    fd.write(self.read())
                except EOFError:
                    break

    h = klass(1, FakeContext(), version)
    h.init()
    h.handle()
    h.close()
    return h

@pytest.mark.usefixtures('cuckoo_cwd')
class TestFileUpload(object):
    @pytest.mark.order1
    def test_success_noversion(self):
        fu = mock_handler_context(FileUpload,
                                  cwd(analysis=1),
                                  ['files/1.exe'],
                                  ['this', 'is', 'a', 'test'])

        with open(cwd("files", "1.exe", analysis=1), "rb") as f:
            assert f.read() == "thisisatest"

        with open(fu.filelog) as f:
            lines = f.readlines()
            blob = json.loads(lines[-1])
            assert blob['filepath'] is None
            assert blob['path'] == "files/1.exe"
            assert blob["pids"] == []

    @pytest.mark.order2
    def test_overwrite(self):
        with pytest.raises(CuckooOperationalError) as e:
            mock_handler_context(FileUpload,
                                 cwd(analysis=1),
                                 ['files/1.exe'],
                                 [])
        e.match("overwrite an existing file")


    def test_success_v2(self):
        fu = mock_handler_context(FileUpload,
                                  cwd(analysis=1),
                                  ['files/2.exe', 'C:\\RealFilename.exe',
                                   '11 12'],
                                  ['second', 'test'],
                                  2)

        with open(cwd("files", "2.exe", analysis=1), "rb") as f:
            assert f.read() == "secondtest"

        with open(fu.filelog) as f:
            lines = f.readlines()
            blob = json.loads(lines[-1])
            assert blob['filepath'] == 'C:\\RealFilename.exe'
            assert blob['path'] == "files/2.exe"
            assert blob["pids"] == [11, 12]


    def invalid_path(self, path):
        with pytest.raises(CuckooOperationalError) as e:
            mock_handler_context(FileUpload, cwd(analysis=1), [path], [])
        e.match("banned path")

    def test_invalid_paths(self):
        self.invalid_path("dummy")
        self.invalid_path("files/p\x00ath.exe")
        self.invalid_path("files/path.exe:$DATA")
        self.invalid_path("notallowed/path.exe")
        self.invalid_path("shots/notallowed/path.jpg")
        self.invalid_path("reports/report.json")
        self.invalid_path("/tmp/foobar")
        self.invalid_path("../hello")
        self.invalid_path("../../foobar")


@pytest.mark.usefixtures('cuckoo_cwd')
class TestLogHandler(object):
    @pytest.mark.order1
    def test_success(self):
        mock_handler_context(LogHandler,
                             cwd(analysis=1),
                             [],
                             ['first\n', 'second\n'])

        with open(cwd("analysis.log", analysis=1), "rb") as f:
            assert f.read() == "first\nsecond\n"

    @pytest.mark.order2
    def test_reopen(self):
        mock_handler_context(LogHandler,
                             cwd(analysis=1),
                             [],
                             ['reopen\n'])

        with open(cwd("analysis.log", analysis=1), "rb") as f:
            data = f.read()
            assert 'WARNING: This log file was re-opened' in data
            assert data.endswith('reopen\n')


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
