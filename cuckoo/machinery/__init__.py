# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.core.plugins import enumerate_plugins
from cuckoo.common.abstracts import Machinery

plugins = enumerate_plugins(
    __file__, "cuckoo.machinery", globals(), Machinery, as_dict=True
)
