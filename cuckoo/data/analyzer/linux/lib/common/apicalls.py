#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from getpass import getuser
import logging
from lib.core.config import Config
from common import sanitize_path, path_for_script, filelines, current_directory

log = logging.getLogger(__name__)


def apicalls(target, **kwargs):
    """
    """
    if not target:
        raise Exception("Invalid target for apicalls()")

    cmd = _stap_command_line(target, **kwargs)
    return cmd

def _stap_command_line(target, **kwargs):
    config = Config(cfg="analysis.conf")
    def has_stap(p):
        only_stap = [fn for fn in os.listdir(p) if fn.startswith("stap_") and fn.endswith(".ko")]
        if only_stap:
            return os.path.join(p, only_stap[0])
        return False
    path_cfg = config.get("analyzer_stap_path", None)
    if path_cfg and os.path.exists(path_cfg):
        path = path_cfg
    elif os.path.exists("/root/.cuckoo") and has_stap("/root/.cuckoo"):
        path = has_stap("/root/.cuckoo")
    elif os.path.exists("/home/user/.cuckoo") and has_stap("/home/user/.cuckoo"):
        path = has_stap("/home/user/.cuckoo")
    else:
        log.warning("Could not find STAP LKM, aborting systemtap analysis.")
        return False

    run_as_root = kwargs.get("run_as_root", False)

    # cmd = ["sudo"]
    # cmd += ["staprun"]
    # cmd += ["-vv"]
    # cmd += ["-o"]
    # cmd += ["stap.log"]
    # cmd += [path]
    cmd = "sudo staprun -vv -o stap.log " + path

    run_as_root = kwargs.get("run_as_root", False)

    if "args" in kwargs:
        target_cmd = '"%s %s"' % (target, " ".join(kwargs["args"]))
    else:
        target_cmd = '"%s"' % (target)

    # When we don't want to run the target as root, we have to drop privileges
    # with `sudo -u current_user` right before calling the target.
    #if not run_as_root:
    #    target_cmd = '"sudo -u %s %s"' % (getuser(), target_cmd)
    #    cmd += "-DSUDO=1"
    #cmd += ["-c", target_cmd]
    cmd += " -c " + target_cmd
    return cmd
