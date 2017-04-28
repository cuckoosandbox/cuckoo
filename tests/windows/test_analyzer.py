# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import mock

from analyzer import Analyzer

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
