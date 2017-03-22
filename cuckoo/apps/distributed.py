# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from cuckoo.distributed.app import create_app
from cuckoo.distributed.instance import (
    scheduler, status_caching, handle_node
)
from cuckoo.misc import decide_cwd

app = None

def cuckoo_distributed(hostname, port, debug):
    app = create_app()
    app.run(host=hostname, port=port, debug=debug)

def cuckoo_distributed_instance(name):
    app = create_app()

    with app.app_context():
        if name == "dist.scheduler":
            scheduler()
        elif name == "dist.status":
            status_caching()
        else:
            handle_node(name)

if os.environ.get("CUCKOO_APP") == "dist":
    decide_cwd(exists=True)
    app = create_app()
