# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo import (
    auxiliary, machinery, processing, reporting, signatures,
)

from cuckoo.misc import version as __version__

# Don't include machinery here as its data structure is different from the
# other plugins - of which multiple are in use at any time.
plugins = {
    "auxiliary": auxiliary.plugins,
    "processing": processing.plugins,
    "reporting": reporting.plugins,
    "signatures": signatures.plugins,
}
