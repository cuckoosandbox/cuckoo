# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random

from lib.common.abstracts import Package
from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError

class Applet(Package):
    """Java Applet analysis package."""
    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def make_html(self, path, class_name):
        html = """
        <html>
            <body>
                <applet archive="%s" code="%s" width="1" height="1">
                </applet>
            </body>
        </html>
        """ % (path, class_name)

        file_name = "".join(random.choice(string.ascii_lowercase) for x in range(6)) + ".html"
        file_path = os.path.join(os.getenv("TEMP"), file_name)
        with open(file_path, "w") as file_handle:
            file_handle.write(html)

        return file_path

    def start(self, path):
        browser = self.get_path("browser")
        dll = self.options.get("dll")
        free = self.options.get("free")
        class_name = self.options.get("class")
        suspended = True
        if free:
            suspended = False

        html_path = self.make_html(path, class_name)

        p = Process()
        if not p.execute(path=browser, args="\"%s\"" % html_path, suspended=suspended):
            raise CuckooPackageError("Unable to execute initial Internet "
                                     "Explorer process, analysis aborted")

        if not free and suspended:
            p.inject(dll)
            p.resume()
            return p.pid
        else:
            return None
