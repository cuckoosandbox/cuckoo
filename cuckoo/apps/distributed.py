# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from cuckoo.misc import decide_cwd

try:
    from cuckoo.distributed.app import create_app
    from cuckoo.distributed.instance import (
        scheduler, status_caching, handle_node
    )
    HAVE_FLASKSQLA = True
except ImportError:
    HAVE_FLASKSQLA = False

app = None

def cuckoo_distributed(hostname, port, debug):
    if not HAVE_FLASKSQLA:
        sys.exit(
            "Please install flask-sqlalchemy (through "
            "`pip install cuckoo[distributed]`)"
        )

    app = create_app()
    app.run(host=hostname, port=port, debug=debug)

def cuckoo_distributed_instance(name):
    if not HAVE_FLASKSQLA:
        sys.exit(
            "Please install flask-sqlalchemy (through "
            "`pip install cuckoo[distributed]`)"
        )

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

    if not HAVE_FLASKSQLA:
        sys.exit(
            "Please install flask-sqlalchemy (through "
            "`pip install cuckoo[distributed]`)"
        )

    app = create_app()
