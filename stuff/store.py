# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: python %s <filepath>" % sys.argv[0]
        exit(1)

    # Takes the file, reverses its contents, and writes it to tests/files/.
    content = open(sys.argv[1], "rb").read()
    filepath = os.path.join("tests", "files", os.path.basename(sys.argv[1]))
    open(filepath, "wb").write(content[::-1])
