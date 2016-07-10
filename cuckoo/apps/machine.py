# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from cuckoo.common.config import Config
from cuckoo.core.database import Database
from cuckoo.misc import cwd

def update_conf(machinery, vmname, ip, platform, options, tags, interface,
                snapshot, resultserver, action=None):
    """Writes the new machine to the relevant configuration file."""
    path = cwd("conf", "%s.conf" % machinery)

    lines = []
    for line in open(path, "rb"):
        line = line.strip()

        if "=" in line and line.split("=")[0].strip() == "machines":
            # Parse all existing labels.
            labels = line.split("=", 1)[1]
            labels = [label.strip() for label in labels.split(",")]

            if action == "add":
                labels.append(vmname)
            elif action == "delete":
                if vmname in labels:
                    labels.remove(vmname)

            line = "machines = %s" % ", ".join(labels)

        lines.append(line)

    if action == "add":
        lines += [
            "",
            "[%s]" % vmname,
            "label = %s" % vmname,
            "platform = %s" % platform,
            "ip = %s" % ip,
        ]

    if options:
        lines.append("options = %s" % options)

    if snapshot:
        lines.append("snapshot = %s" % snapshot)

    if interface:
        lines.append("interface = %s" % interface)

    if resultserver:
        resultserver_ip, resultserver_port = resultserver.split(":")
        lines.append("resultserver_ip = %s" % resultserver_ip)
        lines.append("resultserver_port = %s" % resultserver_port)

    if tags:
        lines.append("tags = %s" % tags)

    open(path, "wb").write("\n".join(lines))

def cuckoo_machine(vmname, add, delete, ip, platform, options, tags,
                   interface, snapshot, resultserver):
    db = Database()
    conf = Config()

    if resultserver:
        resultserver_ip, resultserver_port = resultserver.split(":")
    else:
        resultserver_ip = conf.resultserver.ip
        resultserver_port = conf.resultserver.port

    if add:
        if db.view_machine(vmname):
            sys.exit("A Virtual Machine with this name already exists!")

        db.add_machine(vmname, vmname, ip, platform, options, tags, interface,
                       snapshot, resultserver_ip, int(resultserver_port))
        db.unlock_machine(vmname)

        action = "add"

    if delete:
        # TODO Add a db.del_machine() function for runtime modification.
        action = "delete"

    update_conf(conf.cuckoo.machinery, vmname, ip, platform, options, tags,
                interface, snapshot, resultserver, action=action)
