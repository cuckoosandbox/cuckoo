# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.adb import execute_browser

class default_browser(Package):
    """Default Browser analysis package."""
    def __init__(self,options={}):
        Package(options)

    def start(self, path):
        try:
            execute_browser(path)
        except OSError as e:
            ERROR_MESSAGE = str(e)
            return False

    def check(self):
        return True

    def finish(self):
        return True

