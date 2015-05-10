#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os.path
import sys

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database

def update_conf(machinery, args):
    """Writes the new machine to the relevant configuration file."""
    path = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery)

    lines = []
    for line in open(path, "rb"):
        line = line.strip()

        if line.split("=")[0].strip() == "machines":
            # If there are already one or more labels then append the new
            # label to the list, otherwise make a new list.
            if line.split("=", 1)[1].strip():
                line += ", %s" % args.vmname
            else:
                line += " %s" % args.vmname

        lines.append(line)

    lines += [
        "",
        "[%s]" % args.vmname,
        "label = %s" % args.vmname,
        "platform = %s" % args.platform,
        "ip = %s" % args.ip,
    ]

    if args.snapshot:
        lines.append("snapshot = %s" % args.snapshot)

    if args.interface:
        lines.append("interface = %s" % args.interface)

    if args.resultserver:
        ip, port = args.resultserver.split(":")
        lines.append("resultserver_ip = %s" % ip)
        lines.append("resultserver_port = %s" % port)

    if args.tags:
        lines.append("tags = %s" % args.tags)

    open(path, "wb").write("\n".join(lines))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("vmname", type=str, help="Name of the Virtual Machine.")
    parser.add_argument("--debug", action="store_true", help="Debug log in case of errors.")
    parser.add_argument("--add", action="store_true", help="Add a Virtual Machine.")
    parser.add_argument("--ip", type=str, help="Static IP Address.")
    parser.add_argument("--platform", type=str, default="windows", help="Guest Operating System.")
    parser.add_argument("--tags", type=str, help="Tags for this Virtual Machine.")
    parser.add_argument("--interface", type=str, help="Sniffer interface for this machine.")
    parser.add_argument("--snapshot", type=str, help="Specific Virtual Machine Snapshot to use.")
    parser.add_argument("--resultserver", type=str, help="IP:Port of the Result Server.")
    args = parser.parse_args()

    logging.basicConfig()
    log = logging.getLogger()

    if args.debug:
        log.setLevel(logging.DEBUG)

    db = Database()

    if args.resultserver:
        resultserver_ip, resultserver_port = args.resultserver.split(":")
    else:
        conf = Config()
        resultserver_ip = conf.resultserver.ip
        resultserver_port = conf.resultserver.port

    if args.add:
        if db.view_machine(args.vmname):
            sys.exit("A Virtual Machine with this name already exists!")

        db.add_machine(args.vmname, args.vmname, args.ip, args.platform,
                       args.tags, args.interface, args.snapshot,
                       resultserver_ip, int(resultserver_port))
        db.unlock_machine(args.vmname)

        update_conf(conf.cuckoo.machinery, args)

if __name__ == "__main__":
    main()
