# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Jar(Package):
    """Java analysis package."""
    PATHS = [
        ("ProgramFiles", "Java", "jre7", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre6", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path("Java")
        class_path = self.options.get("class")

        if class_path:
            args = "-cp \"%s\" %s" % (path, class_path)
        else:
            args = "-jar \"%s\"" % path

        return self.execute(java, args)
