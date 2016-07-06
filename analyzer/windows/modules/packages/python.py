# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex

from lib.common.abstracts import Package

class Python(Package):
    """Python analysis package."""

    PATHS = [
        ("HomeDrive", "Python24", "python.exe"),
        ("HomeDrive", "Python25", "python.exe"),
        ("HomeDrive", "Python26", "python.exe"),
        ("HomeDrive", "Python27", "python.exe"),
        ("HomeDrive", "Python32", "python.exe"),
        ("HomeDrive", "Python33", "python.exe"),
        ("HomeDrive", "Python34", "python.exe"),
    ]

    def start(self, path):
        python = self.get_path("Python")
        arguments = self.options.get("arguments", "")

        args = [path] + shlex.split(arguments)
        return self.execute(python, args=args, trigger="file:%s" % path)
