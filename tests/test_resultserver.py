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
import socket
import mock
import errno

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.files import Folders
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.core.resultserver import RESULT_DIRECTORIES, MAX_NETLOG_LINE
from cuckoo.core.resultserver import HandlerContext
from cuckoo.core.resultserver import GeventResultServerWorker
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

    ctx = FakeContext()
    ctx.sock = mock.Mock()
    h = klass(1, ctx, version)
    h.init()
    h.handle()
    h.close()
    return h


class TestHandlerContext(object):
    def test_pointless_busywork(self):
        sock = mock.Mock()
        h = HandlerContext(1, 'does-not-exist', sock)
        assert repr(h) == '<Context for None>'

        h.cancel()
        sock.shutdown.assert_called_with(socket.SHUT_RD)

        # Should not raise
        sock.shutdown.side_effect = socket.error()
        h.cancel()

        err = socket.error()
        err.errno = errno.ECONNRESET
        sock.recv.side_effect = err
        assert h.read() == ''

        err = socket.error()
        err.errno = errno.EPIPE
        sock.recv.side_effect = err
        with pytest.raises(socket.error) as e:
            h.read()

    def test_long_line(self):
        sock = mock.Mock()
        h = HandlerContext(1, 'does-not-exist', sock)
        sock.recv.return_value = 'A' * (MAX_NETLOG_LINE + 1)
        with pytest.raises(CuckooOperationalError) as e:
            h.read_newline()
        assert h.buf is sock.recv.return_value

    def test_line_eof(self):
        sock = mock.Mock()
        h = HandlerContext(1, 'does-not-exist', sock)
        sock.recv.return_value = ''
        with pytest.raises(EOFError) as e:
            h.read_newline()

    def test_buffer(self):
        sock = mock.Mock()
        h = HandlerContext(1, 'does-not-exist', sock)
        sock.recv.return_value = 'first\nsecond\nthird'
        assert h.read_newline() == 'first'
        assert h.buf == 'second\nthird'
        assert h.drain_buffer() == 'second\nthird'
        assert h.buf is None

    def test_copy_limited(self):
        sock = mock.Mock()
        fd = mock.Mock()
        h = HandlerContext(1, 'does-not-exist', sock)
        sock.recv.side_effect = ['A' * 64, '']
        h.copy_to_fd(fd, 32)
        fd.write.assert_has_calls([mock.call('A' * 32),
                                   mock.call('... (truncated)')])
        assert fd.flush.called


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

    @mock.patch('cuckoo.core.resultserver.open_exclusive')
    def test_open_error(self, open_exclusive):
        err = OSError()
        err.errno = errno.EACCES
        open_exclusive.side_effect = err
        with pytest.raises(OSError):
            mock_handler_context(FileUpload,
                                 cwd(analysis=1),
                                 ['files/any.exe'],
                                 [])

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

    @mock.patch('cuckoo.core.resultserver.open_exclusive')
    def test_open_error(self, open_exclusive):
        err = OSError()
        err.errno = errno.EACCES
        open_exclusive.side_effect = err
        with pytest.raises(OSError):
            mock_handler_context(LogHandler, cwd(analysis=1), [], [])


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

    def test_unversioned(self):
        h = mock_handler_context(BsonStore, cwd(analysis=1), [], [], None)
        assert h.fd is None

# Work in progress
class TestWorkerServer(object):
    def test_unregistered(self):
        g = GeventResultServerWorker(('127.0.0.1', 1))
        sock = mock.Mock()
        sock.recv.side_effect = IOError
        g.handle(sock, ('127.0.0.1', 41337))
        # <no effect>

    def test_negotiate(self):
        g = GeventResultServerWorker(('127.0.0.1', 1))
        g.add_task(1, '127.0.0.1')
        assert g.tasks == {'127.0.0.1': 1}
        sock = mock.Mock()
        sock.recv.side_effect = ["LOG\n", "Hello\n", ""]
        g.handle(sock, ('127.0.0.1', 41337))
