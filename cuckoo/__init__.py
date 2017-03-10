# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo import (
    auxiliary, machinery, processing, reporting
)

from cuckoo.misc import version as __version__

signatures = []

# Don't include machinery here as its data structure is different from the
# other plugins - of which multiple are in use at any time.
plugins = {
    "auxiliary": auxiliary.plugins,
    "machinery": machinery.plugins.values(),
    "processing": processing.plugins,
    "reporting": reporting.plugins,
    "signatures": signatures,
}
