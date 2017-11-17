# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from modules.auxiliary.recentfiles import RecentFiles

def test_get_path():
    s = RecentFiles()

    s.options = {}
    assert "Documents" in s.get_path()
    assert os.path.isdir(s.get_path())

    s.options = {
        "recentfiles": "desktop",
    }
    assert "Desktop" in s.get_path()
    assert os.path.isdir(s.get_path())
