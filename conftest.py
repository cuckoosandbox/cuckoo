# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys

from cuckoo.misc import is_windows, is_linux, is_macosx

# Note that collect_ignore is a parameter for pytest so that it knows which
# unit tests to skip etc. In other words, perform platform-specific unit tests
# (in terms of the Cuckoo Analyzer) depending on the current host machine.
collect_ignore = []

if is_windows():
    sys.path.insert(0, "cuckoo/data/analyzer/windows")
    collect_ignore.append("tests/linux")
    collect_ignore.append("tests/darwin")

    # Copy over the monitoring binaries as if we were in a real analysis.
    monitor = open("cuckoo/data/monitor/latest", "rb").read().strip()
    for filename in os.listdir("cuckoo/data/monitor/%s" % monitor):
        shutil.copy(
            "cuckoo/data/monitor/%s/%s" % (monitor, filename),
            "cuckoo/data/analyzer/windows/bin/%s" % filename
        )

if is_linux():
    sys.path.insert(0, "cuckoo/data/analyzer/linux")
    collect_ignore.append("tests/windows")
    collect_ignore.append("tests/darwin")

if is_macosx():
    sys.path.insert(0, "cuckoo/data/analyzer/darwin")
    collect_ignore.append("tests/windows")
    collect_ignore.append("tests/linux")
