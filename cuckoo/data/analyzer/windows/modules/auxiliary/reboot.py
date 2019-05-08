# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path

from lib.common.abstracts import Auxiliary
from lib.common.registry import set_regkey_full

log = logging.getLogger(__name__)

class Reboot(Auxiliary):
    """Prepare the environment to behave as if the VM has been rebooted."""

    def start(self):
        if self.analyzer.config.package != "reboot":
            return

        reboot_path = os.path.join(self.analyzer.path, "reboot.json")
        for line in open(reboot_path, "rb"):
            event = json.loads(line)

            if not hasattr(self, "_handle_%s" % event["category"]):
                log.warning(
                    "Unable to handle reboot event with name %s as it has "
                    "not yet been implemented.", event["category"]
                )
                continue

            getattr(self, "_handle_%s" % event["category"])(event)

    def _handle_regkey_written(self, event):
        regkey, type_, value = event["args"]
        set_regkey_full(regkey, type_, value)

    def _handle_create_process(self, event):
        self.analyzer.reboot.append((event["category"], event["args"]))
