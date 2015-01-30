# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from random import randint

from lib.common.abstracts import Package

class Generic(Package):
    """Generic analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        rand_title = "".join( [chr(randint(0, 128)) for i in xrange(0, randint(1, 10))])
        cmd_args = "/c start /wait it'\"{0}\" \"{1}\"".format(rand_title, path)
        return self.execute(cmd_path, cmd_args)
