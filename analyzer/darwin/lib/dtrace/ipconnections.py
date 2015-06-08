#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from collections import namedtuple
from tempfile import NamedTemporaryFile
from subprocess import Popen
from .fileutils import filelines

connection = namedtuple("connection",
                        "host host_port remote remote_port protocol timestamp")

def ipconnections(target, **kwargs):
    """Returns a list of ip connections made by the target.

    A connection is a named tuple with the following properties:
    host (string), host_port (int), remote_port (string), protocol (string),
    timestamp(int).
    """
    if not target:
		raise Exception("Invalid target for ipconnections()")

    file = NamedTemporaryFile()
    cmd = ["sudo", "/usr/sbin/dtrace", "-C"]
    if "timeout" in kwargs:
        cmd += ["-DANALYSIS_TIMEOUT=%d" % kwargs["timeout"]]
    cmd += ["-s", _ipconnections_path()]
    cmd += ["-o", file.name]
    if "args" in kwargs:
        line = "%s %s" % (_sanitize_path(target), " ".join(kwargs["args"]))
        cmd += ["-c", line]
    else:
        cmd += ["-c", _sanitize_path(target)]

    # The dtrace script will take care of timeout itself, so we just launch
    # it asynchronously
    with open(os.devnull, "w") as f:
        handler = Popen(cmd, stdout=f, stderr=f)

    for entry in filelines(file):
    	if "## ipconnections.d done ##" in entry.strip():
    		break
    	yield _parse_single_entry(entry.strip())
    file.close()

def _sanitize_path(path):
    """ Replace spaces with backslashes+spaces """
    return path.replace(" ", "\\ ")

def _ipconnections_path():
    return os.path.dirname(os.path.abspath(__file__)) + "/ipconnections.d"

#
# Parsing implementation details
#

def _parse_single_entry(entry):
    entry = entry.replace("\\0", "")
    print entry
    parsed = json.loads(entry)

    host        = parsed['host']
    host_port   = parsed['host_port']
    remote      = parsed['remote']
    remote_port = parsed['remote_port']
    protocol    = parsed['protocol']
    timestamp   = parsed['timestamp']
    return connection(host, host_port, remote, remote_port, protocol, timestamp)

if __name__ == "__main__":
    pass
