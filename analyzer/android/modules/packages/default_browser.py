# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.adb import execute_browser

class default_browser(Package):
    """Default Browser analysis package."""
    def __init__(self, options={}):
        super(default_browser, self).__init__(options)

    def start(self, target):
        execute_browser(target)

    def check(self):
        return True

    def finish(self):
        return True
