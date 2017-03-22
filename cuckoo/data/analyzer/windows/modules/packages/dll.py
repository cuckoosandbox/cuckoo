# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shlex
import shutil

from lib.common.abstracts import Package

class Dll(Package):
    """DLL analysis package."""
    PATHS = [
        ("System32", "rundll32.exe"),
    ]

    def start(self, path):
        rundll32 = self.get_path("rundll32.exe")
        function = self.options.get("function", "DllMain")
        arguments = self.options.get("arguments", "")
        loader_name = self.options.get("loader")

        # Check file extension.
        ext = os.path.splitext(path)[-1].lower()

        # If the file doesn't have the proper .dll extension force it
        # and rename it. This is needed for rundll32 to execute correctly.
        # See ticket #354 for details.
        if ext != ".dll":
            new_path = path + ".dll"
            os.rename(path, new_path)
            path = new_path

        args = ["%s,%s" % (path, function)]
        if arguments:
            args += shlex.split(arguments)

        if loader_name:
            loader = os.path.join(os.path.dirname(rundll32), loader_name)
            shutil.copy(rundll32, loader)
            rundll32 = loader

        return self.execute(rundll32, args=args)
