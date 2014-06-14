# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import string
import random

from lib.common.abstracts import Package

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
        class_name = self.options.get("class")
        html_path = self.make_html(path, class_name)
        return self.execute(browser, "\"%s\"" % html_path)
