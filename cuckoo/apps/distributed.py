# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from cuckoo.misc import set_cwd

try:
    from cuckoo.distributed.app import create_app
    from cuckoo.distributed.instance import (
        scheduler, status_caching, handle_node
    )
    HAVE_FLASKSQLA = True
except ImportError:
    HAVE_FLASKSQLA = False

app = None

if os.environ.get("CUCKOO_APP") == "dist":
    # When run under uWSGI the Cuckoo Working Directory will not have been set
    # yet and we'll have to do so ourselves.
    set_cwd(os.environ["CUCKOO_CWD"])

    if not HAVE_FLASKSQLA:
        sys.exit(
            "Please install flask-sqlalchemy (through "
            "`pip install cuckoo[distributed]`)"
        )

    app = create_app()

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
