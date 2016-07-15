#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os.path
import sys

from distributed.app import create_app

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.startup import drop_privileges

logging.basicConfig(level=logging.INFO)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
log = logging.getLogger("cuckoo.distributed")

application = create_app()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="127.0.0.1", help="Host to listen on.")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on.")
    p.add_argument("-u", "--user", type=str, help="Drop user privileges to this user.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    args = p.parse_args()

    if args.user:
        drop_privileges(args.user)

    log.setLevel(logging.DEBUG)
    application.run(host=args.host, port=args.port, debug=True)
