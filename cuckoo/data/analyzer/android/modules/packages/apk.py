# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging

from lib.common.abstracts import Package
from lib.common.utils import install_app, execute_app, get_pid_of
from lib.common.exceptions import CuckooPackageError, CuckooError

log = logging.getLogger(__name__)

class Apk(Package):
    """Apk analysis package."""

    def __init__(self, options={}):
        Package.__init__(self, options)
        pkg_info = options.get("apk_entry", ":").split(":")
        self.package = pkg_info[0]
        self.activity = pkg_info[1]

    def start(self, target):
        """Run analysis package.
        @param target: sample path.
        """
        try:
            install_app(target)
        except RuntimeError as e:
            raise CuckooPackageError(e)

        success = super(Apk, self).execute(self.package)
        if not success:
            try:
                # Try starting it via the activity manager.
                execute_app(self.package, self.activity)
            except RuntimeError as e:
                raise CuckooPackageError(e)

            pid = get_pid_of(self.package)
            if pid is None:
                raise CuckooPackageError(
                    "Failed to execute application. Process not found."
                )
            self.add_pid(pid)
