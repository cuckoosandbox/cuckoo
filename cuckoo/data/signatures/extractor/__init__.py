# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Extractor
from cuckoo.core.plugins import enumerate_plugins

plugins = []
extractors = enumerate_plugins(
    __file__, "signatures.extractor", globals(), Extractor, {}
)
