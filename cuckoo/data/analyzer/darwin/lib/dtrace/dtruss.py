#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from getpass import getuser
from collections import namedtuple
from subprocess import Popen
from tempfile import NamedTemporaryFile

from common import *

syscall = namedtuple("syscall", "name args result errno timestamp pid")


def dtruss(target, **kwargs):
    """Returns a list of syscalls made by a target.

    Every syscall is a named tuple with the following properties:
    name (string), args (list), result (int), errno (int),
    timestamp(int) and pid(int).
    """

    if not target:
        raise Exception("Invalid target for dtruss()")

    output_file = NamedTemporaryFile()

    cmd = ["/bin/bash", path_for_script("dtruss.sh"), "-W", output_file.name, "-f"]
    # Add timeout
    if ("timeout" in kwargs) and (kwargs["timeout"] is not None):
        cmd += ["-K", str(kwargs["timeout"])]
    # Watch for a specific syscall only
    if "syscall" in kwargs:
        watch_specific_syscall = True
        cmd += ["-t", kwargs["syscall"]]
    else:
        watch_specific_syscall = False

    if "run_as_root" in kwargs:
        run_as_root = kwargs["run_as_root"]
    else:
        run_as_root = False

    # When we don't want to run the target as root, we have to drop privileges
    # with `sudo -u current_user` right before calling the target.
    if not run_as_root:
        cmd += ["sudo", "-u", getuser()]
    # Add target path
    cmd += [sanitize_path(target)]
    # Arguments for the target
    if "args" in kwargs:
        cmd += kwargs["args"]

    # The dtrace script will take care of timeout itself, so we just launch
    # it asynchronously
    with open(os.devnull, "w") as f:
        handle = Popen(cmd, stdout=f, stderr=f)

    # If we use `sudo -u` for dropping root privileges, we also have to
    # exclude it's output from the results
    sudo_pid = None

    for entry in filelines(output_file):
        if "## dtruss.sh done ##" in entry.strip():
            break
        syscall = _parse_syscall(entry.strip())
        if syscall is None:
            continue

        # sudo's syscalls will be the first ones, so remember its pid
        if not run_as_root and sudo_pid is None and not watch_specific_syscall:
            sudo_pid = syscall.pid
        elif syscall.pid != sudo_pid:
            yield syscall

    output_file.close()


#
# Parsing implementation details
#

def _parse_syscall(string):
    string = string.replace("\\0", "")
    try:
        parsed = json.loads(string)
    except:
        return None

    name = parsed["syscall"]
    args = parsed["args"]
    result = parsed["retval"]
    errno = parsed["errno"]
    pid = parsed["pid"]
    timestamp = parsed["timestamp"]

    return syscall(name=name, args=args, result=result, errno=errno, pid=pid,
                   timestamp=timestamp)
