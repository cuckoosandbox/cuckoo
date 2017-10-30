# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import pytest
import socket

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
        # Normally (i.e., when not Administrator) the user shouldn't be able
        # to access the lsass.exe process.
        with pytest.raises(CuckooError) as e:
            p.is32bit(process_name="lsass.exe")
        e.match("process access denied$")
