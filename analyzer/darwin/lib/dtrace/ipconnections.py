#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from common import *
from subprocess import Popen
from collections import namedtuple
from tempfile import NamedTemporaryFile

connection = namedtuple("connection",
                        "host host_port remote remote_port protocol timestamp, pid")


def ipconnections(target, **kwargs):
    """Returns a list of ip connections made by the target.

    A connection is a named tuple with the following properties:
    host (string), host_port (int), remote_port (string), protocol (string),
    timestamp(int).
    """
    if not target:
        raise Exception("Invalid target for ipconnections()")

    output_file = NamedTemporaryFile()
    cmd = ["sudo", "/usr/sbin/dtrace", "-C"]
    if "timeout" in kwargs:
        cmd += ["-DANALYSIS_TIMEOUT=%d" % kwargs["timeout"]]
    cmd += ["-s", path_for_script("ipconnections.d")]
    cmd += ["-o", output_file.name]
    if "args" in kwargs:
        line = "%s %s" % (sanitize_path(target), " ".join(kwargs["args"]))
        cmd += ["-c", line]
    else:
        cmd += ["-c", sanitize_path(target)]

    # The dtrace script will take care of timeout itself, so we just launch
    # it asynchronously
    with open(os.devnull, "w") as f:
        handler = Popen(cmd, stdout=f, stderr=f)

    for entry in filelines(output_file):
        if "## ipconnections.d done ##" in entry.strip():
            break
        yield _parse_single_entry(entry.strip())
    output_file.close()


#
# Parsing implementation details
#

def _parse_single_entry(entry):
    entry = entry.replace("\\0", "")
    parsed = json.loads(entry)

    host = parsed['host']
    host_port = parsed['host_port']
    remote = parsed['remote']
    remote_port = parsed['remote_port']
    protocol = parsed['protocol']
    timestamp = parsed['timestamp']
    pid = parsed['pid']
    return connection(host, host_port, remote, remote_port, protocol, timestamp, pid)
