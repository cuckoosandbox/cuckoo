# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.api.adb import dump_droidmon_logs, execute_sample
from lib.api.adb import install_sample, get_package_activity_name
from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Apk(Package):
    """Apk analysis package."""
    def __init__(self, options={}):
        super(Apk, self).__init__(options)
        self.package = ""
        self.activity = ""

    def start(self, path):
        self.package, self.activity = get_package_activity_name(path)
        install_sample(path)
        execute_sample(self.package, self.activity)

    def check(self):
        return True

    def finish(self):
        dump_droidmon_logs(self.package)
        return True
