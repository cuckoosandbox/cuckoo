# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
import subprocess

log = logging.getLogger(__name__)

BUFSIZE = 1024*1024

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
