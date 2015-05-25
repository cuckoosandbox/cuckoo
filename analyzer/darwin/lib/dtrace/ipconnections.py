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
from subprocess import check_call

connection = namedtuple("connection",
                        "host host_port remote remote_port protocol timestamp")

def ipconnections(target, timeout=None):
    """Returns a list of ip connections made by the target.

    A connection is a named tuple with the following properties:
    host (string), host_port (int), remote_port (string), protocol (string),
    timestamp(int).
    """
    file = NamedTemporaryFile()
    cmd = ["sudo", "/usr/sbin/dtrace",
           "-C", "-DANALYSIS_TIMEOUT=%d" % (timeout if timeout != None else -1),
           "-s", _ipconnections_path(),
           "-c", _sanitize_path(target),
           "-o", file.name]

    with open(os.devnull, "w") as f:
        check_call(cmd, stdout=f, stderr=f)
    output = file.read().splitlines()
    file.close()

    # Skip everything above the ipconnections.d's header
    header_idx = output.index("## ipconnections.d ##")
    del output[:header_idx+1]
    return _parse_ipconnections_output(output)

def _sanitize_path(path):
    """ Replace spaces with backslashes+spaces """
    return path.replace(" ", "\\ ")

def _ipconnections_path():
    return os.path.dirname(os.path.abspath(__file__)) + "/ipconnections.d"

#
# Parsing implementation details
#

def _parse_ipconnections_output(output):
    return map(_parse_single_entry, filter(None, output))

def _parse_single_entry(entry):
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
