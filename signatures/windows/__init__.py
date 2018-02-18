# Copyright (C) 2010-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from ..compat import enumerate_signatures

plugins = enumerate_signatures(
    __file__, "windows", globals(), dict(platform="windows")
)
