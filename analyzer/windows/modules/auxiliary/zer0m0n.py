# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import os.path
import platform
import shutil
import _winreg

from lib.api.process import subprocess_checkcall
from lib.common.abstracts import Auxiliary
from lib.common.defines import NTDLL, UNICODE_STRING
from lib.common.exceptions import CuckooError
from lib.common.registry import set_regkey, del_regkey
from lib.core.ioctl import driver_name as random_name

log = logging.getLogger(__name__)

class LoadZer0m0n(Auxiliary):
    """Loads the zer0m0n kernel driver."""

    def start(self):
        if self.options.get("analysis") not in ("both", "kernel"):
            return

        if platform.machine().endswith("64"):
            driver_name = "zer0m0n-x64.sys"
            driver_dir = os.path.expandvars(
                "%SystemRoot%\\sysnative\\drivers"
            )
        else:
            driver_name = "zer0m0n-x86.sys"
            driver_dir = os.path.expandvars(
                "%SystemRoot%\\system32\\drivers"
            )

        if not os.path.exists(os.path.join("bin", driver_name)):
            log.error(
                "zer0m0n driver not found: %s",
                os.path.join("bin", driver_name)
            )
            return

        # Disable the Program Compability Assistant (which would otherwise
        # show an annoying popup about our kernel driver not being signed).
        subprocess_checkcall(["sc", "stop", "PcaSvc"])

        shutil.copy(
            os.path.join("bin", driver_name),
            os.path.join(driver_dir, "%s.sys" % random_name)
        )

        self.set_regkey(
            random_name, "ImagePath", _winreg.REG_SZ,
            "\\SystemRoot\\system32\\drivers\\%s.sys" % random_name
        )
        self.set_regkey(random_name, "Start", _winreg.REG_DWORD, 3)
        self.set_regkey(random_name, "Type", _winreg.REG_DWORD, 1)
        self.set_regkey(random_name, "ErrorControl", _winreg.REG_DWORD, 1)
        self.load_driver(random_name)
        self.del_regkeys(random_name)

        log.info("Successfully loaded the zer0m0n kernel driver.")

    def set_regkey(self, random_name, key, type_, value):
        set_regkey(
            _winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\%s" % random_name,
            key, type_, value
        )

    def del_regkeys(self, random_name):
        del_regkey(
            _winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\%s\\Enum" % random_name
        )

        del_regkey(
            _winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\%s\\Security" % random_name
        )

        del_regkey(
            _winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\%s" % random_name
        )

    def load_driver(self, random_name):
        regkey = (
            u"\\Registry\\Machine\\System"
            u"\\CurrentControlSet\\Services\\%s" % random_name
        )
        us = UNICODE_STRING()
        us.Buffer = regkey
        us.Length = len(regkey) * 2
        us.MaximumLength = us.Length

        status = NTDLL.NtLoadDriver(ctypes.byref(us)) % 2**32
        if status:
            raise CuckooError(
                "Unable to load the zer0m0n driver: 0x%x" % status
            )
