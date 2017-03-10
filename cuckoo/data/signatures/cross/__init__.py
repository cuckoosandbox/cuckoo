# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Signature
from cuckoo.core.plugins import enumerate_plugins

plugins = enumerate_plugins(
    __file__, "signatures.cross", globals(),
    Signature, {}
)
