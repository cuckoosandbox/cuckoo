# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from _winreg import OpenKey, SetValueEx
from _winreg import HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ


from lib.common.abstracts import Auxiliary
from lib.common.rand import random_integer

log = logging.getLogger(__name__)

class Disguise(Auxiliary):
    """Disguise the analysis environment."""

    def change_productid(self):
        """Randomizes Windows ProductId, which is occasionally used by malware
        to detect public setups of Cuckoo, e.g. Malwr.com.
        """
        key = OpenKey(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_SET_VALUE
        )

        value = "{0}-{1}-{2}-{3}".format(
            random_integer(5),
            random_integer(3),
            random_integer(7),
            random_integer(5)
        )

        SetValueEx(key, "ProductId", 0, REG_SZ, value)

    def start(self):
        self.change_productid()
        return True
