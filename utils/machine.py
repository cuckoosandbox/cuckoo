#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os.path
import sys

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database

def update_conf(machinery, args, action=None):
    """Writes the new machine to the relevant configuration file."""
    path = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery)

    lines = []
    for line in open(path, "rb"):
        line = line.strip()

        if "=" in line and line.split("=")[0].strip() == "machines":
            # Parse all existing labels.
            labels = line.split("=", 1)[1]
            labels = [label.strip() for label in labels.split(",")]

            if action == "add":
                labels.append(args.vmname)
            elif action == "delete":
                if args.vmname in labels:
                    labels.remove(args.vmname)

            line = "machines = %s" % ", ".join(labels)

        lines.append(line)

    if action == "add":
        lines += [
            "",
            "[%s]" % args.vmname,
            "label = %s" % args.vmname,
            "platform = %s" % args.platform,
            "ip = %s" % args.ip,
        ]

    if args.options:
        lines.append("options = %s" % args.options)

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
    parser.add_argument("--delete", action="store_true", help="Delete a Virtual Machine.")
    parser.add_argument("--ip", type=str, help="Static IP Address.")
    parser.add_argument("--platform", type=str, default="windows", help="Guest Operating System.")
    parser.add_argument("--options", type=str, help="Machine options.")
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
    conf = Config()

    if args.resultserver:
        resultserver_ip, resultserver_port = args.resultserver.split(":")
    else:
        resultserver_ip = conf.resultserver.ip
        resultserver_port = conf.resultserver.port

    if args.add:
        if db.view_machine(args.vmname):
            sys.exit("A Virtual Machine with this name already exists!")

        db.add_machine(args.vmname, args.vmname, args.ip, args.platform,
                       args.options, args.tags, args.interface, args.snapshot,
                       resultserver_ip, int(resultserver_port))
        db.unlock_machine(args.vmname)

        update_conf(conf.cuckoo.machinery, args, action="add")

    if args.delete:
        # TODO Add a db.del_machine() function for runtime modification.
        update_conf(conf.cuckoo.machinery, args, action="delete")

if __name__ == "__main__":
    main()
