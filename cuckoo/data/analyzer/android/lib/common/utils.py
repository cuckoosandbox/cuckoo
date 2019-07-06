# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import random
import string
import json
import subprocess

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

def determine_device_arch():
    """Determine the architecture of the device."""
    try:
        args = ["getprop", "ro.product.cpu.abi"]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = list(map(bytes.decode, p.communicate()))

        if p.returncode:
            raise OSError(err)
    except OSError:
        return

    supported_archs = ["arm64", "arm", "x86_64", "x86"]
    for arch in supported_archs:
        if arch in out:
            return arch

def random_str(length=8):
    letters = string.ascii_letters
    return "".join(random.choice(letters) for _ in range(length))

# https://stackoverflow.com/a/24349916/7267323
# Compare two xml.etree.ElementTree nodes
def etree_compare(e1, e2):
    if e1.tag != e2.tag:
        return False
    if e1.text != e2.text:
        return False
    if e1.tail != e2.tail:
        return False
    if e1.attrib != e2.attrib:
        return False
    if len(e1) != len(e2):
        return False
    return all(etree_compare(c1, c2) for c1, c2 in zip(e1, e2))
