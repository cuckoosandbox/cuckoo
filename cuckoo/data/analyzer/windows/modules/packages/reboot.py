# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Reboot(Package):
    """Reboot analysis package."""

    def _handle_create_process(self, filepath, command_line, source):
        self.pids.append(self.execute(filepath, command_line))

    def start(self, path):
        for category, args in self.analyzer.reboot:
            if not hasattr(self, "_handle_%s" % category):
                log.warning("Unhandled reboot command: %s", category)
                continue

            getattr(self, "_handle_%s" % category)(*args)
