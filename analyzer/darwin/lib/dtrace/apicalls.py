#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from common import *
from getpass import getuser
from subprocess import Popen
from collections import namedtuple
from tempfile import NamedTemporaryFile

apicall = namedtuple("apicall", "api args retval timestamp pid")

def apicalls(target, **kwargs):
    """
    """
    if not target:
		raise Exception("Invalid target for apicalls()")

    file = NamedTemporaryFile()
    cmd = ["sudo", "/usr/sbin/dtrace", "-C"]
    if "timeout" in kwargs:
        cmd += ["-DANALYSIS_TIMEOUT=%d" % kwargs["timeout"]]
    cmd += ["-s", path_for_script("apicalls.d")]
    cmd += ["-DROOT=1"]
    cmd += ["-o", file.name]
    cmd += ["-DOUTPUT_FILE=\"%s\"" % file.name]

    if "run_as_root" in kwargs:
        run_as_root = kwargs["run_as_root"]
    else:
        run_as_root = False

    target_cmd = ""
    if "args" in kwargs:
        target_cmd = "%s %s" % (sanitize_path(target), " ".join(kwargs["args"]))
    else:
        target_cmd = sanitize_path(target)
    # When we don't want to run the target as root, we have to drop privileges
    # with `sudo -u current_user` right before calling the target.
    if not run_as_root:
        target_cmd = "sudo -u %s %s" % (getuser(), target_cmd)

    cmd += ["-c", target_cmd]

    # The dtrace script will take care of timeout itself, so we just launch
    # it asynchronously
    with open(os.devnull, "w") as f:
        handler = Popen(cmd, stdout=f, stderr=f, cwd=current_directory())

    # If we use `sudo -u` for dropping root privileges, we also have to
	# exclude it's output from the results
	sudo_pid = None

    for entry in filelines(file):
    	if "## apicalls.d done ##" in entry.strip():
    		break
        if len(entry.strip()) == 0: continue

        call = _parse_entry(entry.strip())
        if not run_as_root and sudo_pid is None:
            sudo_pid = call.pid
        elif call.pid != sudo_pid:
            yield call
    file.close()


def _parse_entry(entry):
    entry = entry.replace("\\0", "")
    parsed = json.loads(entry)

    api       = parsed['api']
    args      = parsed['args']
    retval    = parsed['retval']
    timestamp = parsed['timestamp']
    pid       = parsed['pid']

    return apicall(api, args, retval, timestamp, pid)

#
# Standalone app
# TODO(rodionovd): implement a standalone version of this module

if __name__ == "__main__":
    pass
