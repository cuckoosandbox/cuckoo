# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging

from lib.api.adb import dump_droidmon_logs, execute_sample, install_sample
from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Apk(Package):
    """Apk analysis package."""
    def __init__(self, options={}):
        super(Apk, self).__init__(options)

        self.package, self.activity = options.get("apk_entry", ":").split(":")

    def start(self, path):
        install_sample(path)
        execute_sample(self.package, self.activity)

    def check(self):
        return True

    def finish(self):
        dump_droidmon_logs(self.package)
        return True
