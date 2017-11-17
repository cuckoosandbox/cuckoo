# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.api.dse import Capcom
from lib.api.process import subprocess_checkcall
from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooError
from lib.core.driver import Driver
from lib.core.ioctl import driver_name as random_name

log = logging.getLogger(__name__)

class LoadZer0m0n(Auxiliary):
    """Loads the zer0m0n kernel driver."""

    def init(self):
        self.capcom = None

    def start(self):
        if self.options.get("analysis") not in ("both", "kernel"):
            return

        try:
            self.capcom = Capcom()
            self.capcom.install()
        except CuckooError as e:
            log.error("Driver issue: %s", e)
            return

        self.capcom.dse(False)

        try:
            d = Driver("zer0m0n", random_name)
        except CuckooError as e:
            log.error("Driver issue: %s", e)
            return

        # Disable the Program Compability Assistant (which would otherwise
        # show an annoying popup about our kernel driver not being signed).
        subprocess_checkcall(["sc", "stop", "PcaSvc"])

        try:
            d.install()
            log.info("Successfully loaded the zer0m0n kernel driver.")
        except CuckooError as e:
            log.error("Error loading zer0m0n: %s", e)

        self.capcom.dse(True)
