# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from random import randint

from lib.common.abstracts import Package

class Wget(Package):


    def start(self, path):
        os.system("wget \"%s\" -O /tmp/file_malwr" % path)
        os.chmod("/tmp/file_malwr", 0o755)
        return self.execute(["sh", "-c", "/tmp/file_malwr"])
