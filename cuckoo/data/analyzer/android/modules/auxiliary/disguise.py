# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

class Disguise(Auxiliary):
    """Disguise the analysis environment."""

    FAKE_CPUINFO = "/data/local/tmp/fake-cpuinfo"
    FAKE_DRIVERS = "/data/local/tmp/fake-drivers"

    def rebind_file(self, source_filepath, dest_filepath):
        if not os.path.isfile(source_filepath):
            return
        
        try:
            args = ["mount", source_filepath, dest_filepath]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            err = p.communicate()[1].decode()

            if p.returncode:
                raise OSError(err)
        except OSError as e:
            log.error("Failed to bind file %s: %s", source_filepath, e)

    def rebind_cpuinfo(self):
        self.rebind_file(self.FAKE_CPUINFO, "/proc/cpuinfo")

    def rebind_drivers(self):
        self.rebind_file(self.FAKE_DRIVERS, "/proc/tty/drivers")

    def start(self):
        self.rebind_cpuinfo()
        self.rebind_drivers()
