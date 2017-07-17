# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import socket

from lib.common.results import NetlogFile, upload_to_host
from lib.core.startup import init_logging

@mock.patch("socket.create_connection")
def test_netlogfile_init(p):
    nf = NetlogFile()
    nf.init(u"dump-\u202e.exe")
    nf.sock = None
    nf.init(u"dump-\u202e.exe", u"file-\u202e.exe")
    a, b = p.return_value.sendall.call_args_list
    assert a[0][0] == str(a[0][0])
    assert b[0][0] == str(b[0][0])

def test_upload_to_host():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(5)

    with open("analysis.conf", "wb") as f:
        f.write("[hello]\nip = %s\nport = %d" % s.getsockname())

    handlers = logging.getLogger().handlers[:]
    init_logging()

    # Test file not found exception.
    upload_to_host(u"\u202ethisis404.exe", "1.exe")
    c, _ = s.accept()
    assert "Exception uploading file u'\\u202e" in c.recv(0x1000)
    c, _ = s.accept()
    assert "FILE 2\n1.exe\n\xe2\x80\xaethisis404.exe\n" in c.recv(0x1000)

    # Test correct upload.
    upload_to_host(__file__, "1.py", ["1", "2", "3"])
    c, _ = s.accept()
    assert c.recv(0x1000).startswith(
        "FILE 2\n1.py\n%s\n1 2 3\n# Copyright (C" % __file__
    )

    logging.getLogger().handlers = handlers
