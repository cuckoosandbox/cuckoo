# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.misc import cwd, set_cwd
from cuckoo.distributed.distributed.app import create_app

app = None

# When run under uWSGI the Cuckoo Working Directory will not have been set
# yet and we'll have to do so ourselves.
if not cwd() and os.environ.get("CUCKOO_FORCE"):
    set_cwd(os.environ["CUCKOO_FORCE"])
    app = create_app()

def cuckoo_distributed(hostname, port, debug):
    (app or create_app()).run(host=hostname, port=port, debug=debug)
