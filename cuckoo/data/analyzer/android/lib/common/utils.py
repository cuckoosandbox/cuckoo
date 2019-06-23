# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
import subprocess

log = logging.getLogger(__name__)

BUFSIZE = 1024*1024

def install_app(apk_path):
        """Install sample via package manager.
        @raise CuckooError: failed to install sample.
        """
        log.info("Installing sample on the device: %s", apk_path)
        
        p = subprocess.Popen(
            ["/system/bin/sh", "/system/bin/pm", "install", "-r", apk_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        err = p.communicate()[1].decode('utf-8')

        if p.returncode != 0:
            raise RuntimeError("Error installing sample: %s" % err)
        log.info("Installed sample successfully.")

def execute_app(package, activity):
        """Execute sample via activity manager.
        @raise CuckooError: failed to execute sample.
        """
        log.info("Executing sample on the device with activity manager..")

        package_activity = "%s/%s" % (package, activity)
        p = subprocess.Popen(
            ["/system/bin/sh", "/system/bin/am", "start",
            "-n", package_activity], stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        out, err = [x.decode('utf-8') for x in p.communicate()]

        if p.returncode != 0:
            raise RuntimeError("Error executing package activity: %s" % err)
        log.info("Executed package activity: %s", out)

def get_pid_of(pkg_name):
    """Get PID of an Android application process via its package name
    @return: the process id.
    """
    p = subprocess.Popen(
        ["/system/bin/top", "-bn", "1"], stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    )
    out = p.communicate()[0].decode('utf-8')

    pid = None
    if p.returncode != 0:
        return pid
    for line in out.split("\n"):
        splitLine = line.split(" ")
        if pkg_name in splitLine:
            pid = int(splitLine[1])
            break

    return pid

def load_configs(dir_path):
    """Load all JSON configuration files in a directory.
    @param dir_path: path of directory.
    """
    obj = {}
    for fname in os.listdir(dir_path):
        if not fname.endswith(".json"):
            continue

        fpath = os.path.join(dir_path, fname)
        with open(fpath, "r") as fd:
            obj[os.path.splitext(fname)[0]] = json.load(fd)

    return obj

def hash_file(method, path):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(path, "rb")
    h = method()
    while True:
        buf = f.read(BUFSIZE)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

def roachify_procmem(dump_buffer):
    pass
