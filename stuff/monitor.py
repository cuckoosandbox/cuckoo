#!/usr/bin/env python
# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import os
import requests
import sys
import tarfile

URL = "https://github.com/cuckoosandbox/community/archive/%s.tar.gz"

if __name__ == "__main__":
    if not os.path.lexists("cuckoo/data/monitor/latest"):
        print "Usage: python %s <branch> <hash>" % sys.argv[0]
        print "This script must be run from Cuckoo repository root!"
        exit(1)

    branch, hash_ = "master", None

    if os.path.isfile("cuckoo/data/monitor/latest"):
        hash_ = open("cuckoo/data/monitor/latest", "rb").read().strip()
    elif os.path.islink("cuckoo/data/monitor/latest"):
        hash_ = os.readlink("cuckoo/data/monitor/latest")

    if len(sys.argv) == 3:
        branch, hash_ = sys.argv[1], sys.argv[2]
    elif len(sys.argv) == 2:
        branch = sys.argv[1]

    # No hash could be determined?
    if hash_ is None:
        print "Usage: python %s <branch> <hash>" % sys.argv[0]
        exit(1)

    if not os.path.exists("cuckoo/data/monitor/%s" % hash_):
        os.mkdir("cuckoo/data/monitor/%s" % hash_)

    print "Fetching Cuckoo Community archive, this may take a little while."
    r = requests.get(URL % branch)
    t = tarfile.TarFile.open(fileobj=io.BytesIO(r.content), mode="r:gz")

    # Root directory name.
    root = t.next().name.split("/")[0]

    # Extract all files for this monitor hash.
    for info in t.getmembers():
        if info.name.startswith("%s/data/monitor/%s/" % (root, hash_)):
            print "Extracting..", info.name
            filepath = os.path.join("cuckoo/data/monitor/%s/%s" % (
                hash_, os.path.basename(info.name)
            ))
            open(filepath, "wb").write(t.extractfile(info).read())

    print "You're good to go now!"
