# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import mock

from analyzer import Analyzer, Files
from lib.core.startup import init_logging

osversion = collections.namedtuple("Version", ["major", "minor"])

def test_analyzer():
    """Simply imports the analyzer module to at least load most of the code."""
    import analyzer

    analyzer  # Fake usage.

@mock.patch("sys.getwindowsversion")
def test_pipe_path_winxp(p):
    a = Analyzer()

    p.return_value = osversion(5, 1)
    assert a.get_pipe_path("foo") == "\\\\.\\PIPE\\foo"

    p.return_value = osversion(6, 1)
    assert a.get_pipe_path("foo") == "\\??\\PIPE\\foo"

@mock.patch("socket.create_connection")
def test_add_file_unicode(p):
    with open("analysis.conf", "wb") as f:
        f.write("[foo]\nip = 127.0.0.1\nport = 54321")
    handlers = logging.getLogger().handlers[:]
    init_logging()
    Files().add_file("\xe2\x80\xae".decode("utf8"))
    logging.getLogger().handlers = handlers
