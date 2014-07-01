# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Dll(Package):
    """DLL analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "DllMain")
        arguments = self.options.get("arguments")

        args = "{0},{1}".format(path, function)
        if arguments:
            args += " {0}".format(arguments)

        return self.execute(rundll32, args)
