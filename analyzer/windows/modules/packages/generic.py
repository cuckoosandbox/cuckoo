# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from random import randint

from lib.common.abstracts import Package

class Generic(Package):
    """Generic analysis package.
    The sample is started using START command in a cmd.exe prompt.
    """
    PATHS = [
        ("System32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")

        # Create random cmd.exe window title.
        rand_title = "".join([chr(randint(0, 128)) for i in xrange(0, randint(1, 10))])

        # START syntax.
        # See: https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/start.mspx?mfr=true
        # start ["title"] [/dPath] [/i] [/min] [/max] [{/separate | /shared}]
        # [{/low | /normal | /high | /realtime | /abovenormal | belownormal}]
        # [/wait] [/b] [FileName] [parameters]
        args = ["/c", "start", "/wait", rand_title, path]
        return self.execute(cmd_path, args=args)
