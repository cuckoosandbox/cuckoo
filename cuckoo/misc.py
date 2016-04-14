# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import requests
import StringIO
import tarfile

log = logging.getLogger(__name__)

# Cuckoo Working Directory base path.
_root = None

def set_cwd(path):
    global _root
    _root = path

def cwd(*args):
    """Returns absolute path to this file in its Cuckoo Working Directory."""
    return os.path.join(_root, *args)

def mkdir(*args):
    """Create a directory without throwing exceptions if it already exists."""
    dirpath = os.path.join(*args)
    if not os.path.isdir(dirpath):
        os.mkdir(dirpath)

URL = "https://github.com/cuckoosandbox/community/archive/%s.tar.gz"

def fetch_community(branch="master", force=False, filepath=None):
    if filepath:
        buf = open(filepath, "rb").read()
    else:
        buf = requests.get(URL % branch).content

    t = tarfile.TarFile.open(fileobj=StringIO.StringIO(buf), mode="r:gz")

    folders = {
        os.path.join("modules", "signatures"): "signatures",
        os.path.join("data", "monitor"): "monitor",
        os.path.join("agent"): "agent",
    }

    members = t.getmembers()

    for tarfolder, outfolder in folders.items():
        mkdir(cwd(outfolder))

        # E.g., "community-master/modules/signatures".
        name_start = "%s/%s" % (members[0].name, tarfolder)
        for member in members:
            if not member.name.startswith(name_start) or \
                    name_start == member.name:
                continue

            filepath = cwd(outfolder, member.name[len(name_start)+1:])
            if member.isdir():
                mkdir(filepath)
                continue

            # TODO Ask for confirmation as we used to do.
            if os.path.exists(filepath) and not force:
                log.info(
                    "Not overwriting file which already exists: %s",
                    member.name
                )
                continue

            if member.issym():
                t.makelink(member, filepath)
                continue

            open(filepath, "wb").write(t.extractfile(member).read())
