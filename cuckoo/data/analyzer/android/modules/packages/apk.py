# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import subprocess

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError, CuckooError

log = logging.getLogger(__name__)

class Apk(Package):
    """Apk analysis package."""

    def __init__(self, options={}, analyzer=None):
        Package.__init__(self, options, analyzer)

        pkg_info = options.get("apk_entry", ":").split(":")
        self.package = pkg_info[0]
        self.activity = pkg_info[1]

    def start(self, target):
        """Run analysis package.
        @param target: sample path.
        """
        self._install_app(target)

        success = super(Apk, self).execute(self.package)
        if not success:
            # Try starting it via the activity manager.
            self._execute_app()

            pid = self._get_pid()
            if pid is None:
                raise CuckooPackageError(
                    "Failed to execute application. Process not found."
                )
            self.add_pid(pid)

    def _install_app(self, apk_path):
        """Install sample via package manager.
        @raise CuckooError: failed to install sample.
        """
        log.info("Installing sample on the device: %s", apk_path)
        
        try:
            args = [
                "/system/bin/sh", "/system/bin/pm",
                "install", "-r", apk_path
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            err = p.communicate()[1].decode()

            if p.returncode:
                raise OSError(err)
            log.info("Sample installed successfully.")
        except OSError as e:
            raise CuckooPackageError("Error installing sample: %s" % e)

    def _execute_app(self):
        """Execute sample via activity manager.
        @raise CuckooError: failed to execute sample.
        """
        log.info(
            "Executing sample on the device via the activity manager."
        )

        try:
            args = [
                "/system/bin/sh", "/system/bin/am", 
                "start", "-n", "%s/%s" % (self.package, self.activity)
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = p.communicate()
            
            if p.returncode:
                raise OSError(err.decode())
            log.info("Executed package activity: %s", out.decode())
        except OSError as e:
            raise CuckooPackageError(
                "Error executing package activity: %s" % e
            )

    def _get_pid(self):
        """Get PID of an Android application process via its package name
        @return: the process id.
        """
        try:
            args = ["/system/bin/top", "-bn", "1"]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out = p.communicate()[0].decode()

            if p.returncode:
                return None
        except OSError as e:
            raise CuckooPackageError(
                "Failed to get PID of package %s: %s" % (self.package, e)
            )

        for line in out.splitlines():
            splitLine = line.split(" ")
            if self.package in splitLine:
                return int(splitLine[1])
