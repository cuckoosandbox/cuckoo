# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.misc import cwd

class settings(object):
    """Settings object containing the various configurable components of
    Distributed Cuckoo."""

def init_settings():
    s = {}
    execfile(cwd("distributed", "settings.py"), s)

    for key, value in s.items():
        if key.startswith("_"):
            continue

        setattr(settings, key, value)
