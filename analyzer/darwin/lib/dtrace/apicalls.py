#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from common import *
from getpass import getuser
from subprocess import Popen
from collections import namedtuple
from tempfile import NamedTemporaryFile

apicall = namedtuple("apicall", "api args retval timestamp pid ppid tid")


def apicalls(target, **kwargs):
    """
    """
    if not target:
        raise Exception("Invalid target for apicalls()")

    output_file = NamedTemporaryFile()

    # dtrace must be run as root on OS X
    cmd = ["sudo", "/usr/sbin/dtrace"]
    # Use -C for running clang's C preprocessor over the script
    cmd += ["-C"]
    # Use -I for adding a current directory to the search path for #includes
    cmd += ["-I./"]
    # Use -Z to allow probe descriptions that match zero probes in a target
    cmd += ["-Z"]
    if "timeout" in kwargs:
        cmd += ["-DANALYSIS_TIMEOUT=%d" % kwargs["timeout"]]
    cmd += ["-s", path_for_script("apicalls.d")]
    cmd += ["-DTOPLEVELSCRIPT=1"]
    cmd += ["-o", output_file.name]
    cmd += ["-DOUTPUT_FILE=\"%s\"" % output_file.name]

    if "run_as_root" in kwargs:
        run_as_root = kwargs["run_as_root"]
    else:
        run_as_root = False

    if "args" in kwargs:
        target_cmd = "%s %s" % (sanitize_path(target), " ".join(kwargs["args"]))
    else:
        target_cmd = sanitize_path(target)
    # When we don't want to run the target as root, we have to drop privileges
    # with `sudo -u current_user` right before calling the target.
    if not run_as_root:
        target_cmd = "sudo -u %s %s" % (getuser(), target_cmd)
        cmd += ["-DSUDO=1"]

    cmd += ["-c", target_cmd]

    # The dtrace script will take care of timeout itself, so we just launch
    # it asynchronously
    with open(os.devnull, "w") as null:
        _ = Popen(cmd, stdout=null, stderr=null, cwd=current_directory())

    for entry in filelines(output_file):
        value = entry.strip()
        if "## apicalls.d done ##" in value:
            break
        if len(value) == 0:
            continue
        yield _parse_entry(value)
    output_file.close()


def _parse_entry(entry):
    parsed = json.loads(entry.replace("\\0", ""))

    api       = parsed['api']
    args      = _stringify_args(parsed['args'])
    retval    = parsed['retval']
    # Convert milliseconds to floating point seconds
    timestamp = float(parsed['timestamp']) / 1000
    pid       = parsed['pid']
    ppid      = parsed['ppid']
    tid       = parsed['tid']

    return apicall(api, args, retval, timestamp, pid, ppid, tid)

def _stringify_args(args):
    """ Converts each argument into a string.
    In case of integers, it's a hex string. Other types are converted with str() """
    new_args = []
    for item in args:
        if isinstance(item, (int, long)):
            new_args.append("%#lx" % item)
        else:
            new_args.append(str(item))
    return new_args
