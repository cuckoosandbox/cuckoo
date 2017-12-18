# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
import sys

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: python %s <setup.py> <version>" % sys.argv[0]
        exit(1)

    # Patches the version="..." string in setup.py.
    buf = open(sys.argv[1], "rb").read()
    buf = re.sub('version="(.*)"', 'version="%s"' % sys.argv[2], buf)
    open(sys.argv[1], "wb").write(buf)
