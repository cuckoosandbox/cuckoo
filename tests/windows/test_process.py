# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import socket

from lib.api.process import Process
from lib.core.startup import init_logging

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
