# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import gevent.monkey
    gevent.monkey.patch_all()
    HAVE_GEVENT = True
except ImportError:
    HAVE_GEVENT = False

import logging
import os
import time
import sys

from cuckoo.distributed.app import create_app
from cuckoo.distributed.db import Node
from cuckoo.distributed.instance import scheduler, handle_node
from cuckoo.misc import cwd, decide_cwd

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("cuckoo.distributed.worker")

def with_app(name, fn, *args, **kwargs):
    while True:
        try:
            log.debug("Starting out with instance: %s", name)
            with app.app_context():
                fn(*args, **kwargs)
        except Exception as e:
            log.info("An exception occurred in instance %s: %s", name, e)

        time.sleep(15)

def spawner():
    while True:
        for node in Node.query.filter_by(mode="normal").all():
            tn = node.name, node.enabled
            tr = node.name, not node.enabled

            if tn in workers:
                continue

            # This is a new worker.
            if tr not in workers:
                if node.enabled:
                    log.debug("Started new worker: %s", node.name)
                    workers[tn] = gevent.spawn(
                        with_app, node.name, handle_node, node.name
                    )
                else:
                    log.debug("Registered disabled worker: %s", node.name)
                    workers[tn] = None
                continue

            # This worker was toggled.
            if node.enabled:
                log.debug("Resumed worker: %s", node.name)
                workers[tn] = gevent.spawn(
                    with_app, node.name, handle_node, node.name
                )
                workers.pop(tr)
            else:
                log.debug("Paused worker: %s", node.name)
                workers.pop(tr).kill()
                workers[tn] = None

        time.sleep(5)

if os.environ.get("CUCKOO_APP") == "worker":
    decide_cwd(exists=True)

    if not HAVE_GEVENT:
        sys.exit(
            "Please install Distributed Cuckoo dependencies (through "
            "`pip install cuckoo[distributed]`)"
        )

    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    fh = logging.handlers.WatchedFileHandler(cwd("log", "distributed.log"))
    fh.setFormatter(formatter)
    logging.getLogger().addHandler(fh)

    # Create the Flask object and push its context so that we can reuse the
    # database connection throughout our script.
    app = create_app()

    workers = {
        ("dist.scheduler", True): gevent.spawn(
            with_app, "dist.scheduler", scheduler
        ),
        ("dist.status", True): gevent.spawn(
            with_app, "dist.status", scheduler
        ),
    }

    with_app("dist.spawner", spawner)
