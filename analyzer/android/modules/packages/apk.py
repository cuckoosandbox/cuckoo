# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import re
import subprocess
from lib.api.adb import dump_droidmon_logs,execute_sample,install_sample,get_package_activity_name
from lib.common.utils import send_file
from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.common.results import NetlogFile
from time import sleep

log = logging.getLogger()


class Apk(Package):
    """Apk analysis package."""
    def __init__(self,options={}):
        Package(options)
        self.package=""
        self.activity=""


    def start(self, path):
        self.package, self.activity=get_package_activity_name(path)
        install_sample(path)
        execute_sample(self.package,self.activity)

    def check(self):
        return True

    def finish(self):
        dump_droidmon_logs(self.package)
        return True

