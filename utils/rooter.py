#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import grp
import json
import logging
import os.path
import socket
import stat
import sys

handlers = {
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cuckoo", help="Unix socket group")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("cuckoo-rooter")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if os.path.exists(args.socket):
        os.remove(args.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(args.socket)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    os.chown(args.socket, 0, grp.getgrnam(args.group).gr_gid)
    os.chmod(args.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    while True:
        command = server.recv(4096)

        try:
            obj = json.loads(command)
        except:
            log.info("Received invalid request: %r", command)
            continue

        command = obj.get("command")
        args = obj.get("args", [])
        kwargs = obj.get("kwargs", {})

        if not isinstance(command, basestring) or command not in handlers:
            log.info("Received incorrect command: %r", command)
            continue

        if not isinstance(args, (tuple, list)):
            log.info("Invalid arguments type: %r", args)
            continue

        if not isinstance(kwargs, dict):
            log.info("Invalid keyword arguments: %r", kwargs)
            continue

        for arg in args + kwargs.keys() + kwargs.values():
            if not isinstance(arg, (int, long, basestring)):
                log.info("Invalid argument detected: %r", arg)
                break
        else:
            handlers[command](*args, **kwargs)
