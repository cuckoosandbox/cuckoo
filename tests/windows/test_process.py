# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import pytest
import socket
import subprocess
import sys

from lib.api.process import Process
from lib.common.exceptions import CuckooError
from lib.core.startup import init_logging
from tests.utils import chdir

def test_execute_correct_logging():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)

    with open("analysis.conf", "wb") as f:
        f.write("[hello]\nip = %s\nport = %d" % s.getsockname())

    handlers = logging.getLogger().handlers[:]
    init_logging()
    Process().execute(u"unicodefile\u202ethatdoesnotexist")
    logging.getLogger().handlers = handlers

    c, _ = s.accept()
    assert "202e" in c.recv(0x1000)

def test_is32bit_path():
    p = Process()

    mzdos0 = os.path.abspath("tests/files/mzdos0")
    icardres = os.path.abspath("tests/files/icardres.dll")

    with chdir("cuckoo/data/analyzer/windows"):
        # File not found.
        with pytest.raises(CuckooError) as e:
            p.is32bit(path="thisisnotafile")
        e.match("File not found")

        # No MZ header.
        with pytest.raises(CuckooError) as e:
            p.is32bit(path=__file__)
        e.match("returned by is32bit")
        e.match("Invalid DOS file")

        # This is a MZ-DOS executable rather than a PE file.
        assert p.is32bit(path=mzdos0) is True

        # TODO Add a 32-bit PE executable.

        # This is a 64-bit PE file.
        assert p.is32bit(path=icardres) is False

def test_is32bit_process():
    p = Process()

    with chdir("cuckoo/data/analyzer/windows"):
        # Normally the user shouldn't be able to access the SYSTEM process.
        with pytest.raises(CuckooError) as e:
            p.is32bit(pid=4)
        e.match("process access denied$")

def test_exec_unicode():
    # This isn't possible by default on Python 2.7, however, since we patch
    # the subprocess internals, we make it work. Test that it actually works.
    with open(u"uni\u1234.bat", "wb") as f:
        f.write("echo test > uni-hello.txt")
    assert not subprocess.call(["cmd.exe", "/c", u"uni\u1234.bat"])
    assert open("uni-hello.txt", "rb").read().strip() == "test"

def test_parent_pid():
    assert Process(os.getpid()).get_parent_pid() is not None
