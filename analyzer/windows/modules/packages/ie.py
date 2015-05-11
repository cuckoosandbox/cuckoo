# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import OpenKey, SetValueEx, CloseKey
from _winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER
from _winreg import KEY_SET_VALUE, REG_DWORD, REG_SZ

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError

IESETTINGS = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

class IE(Package):
    """Internet Explorer analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    REGKEYS = [
        {
            "key": HKEY_CURRENT_USER,
            "subkey": "Software\\Microsoft\\Internet Explorer\\Main",
            "values": {
                # "Would you like Internet Explorer as default browser?"
                "Check_Associations": "no",
            },
        },
        {
            "key": HKEY_CURRENT_USER,
            "subkey": "Software\\Microsoft\\Internet Explorer\\Security",
            "values": {
                "Safety Warning Level": "Low",
                "Sending_Security": "Low",
                "Viewing_Security": "Low",
            },
        },
        {
            "key": HKEY_LOCAL_MACHINE,
            "subkey": "Software\\Microsoft\\Internet Explorer\\Main",
            "values": {
                # Disable Security Settings Check.
                "DisableSecuritySettingsCheck": 1,
            },
        },
        {
            "key": HKEY_CURRENT_USER,
            "subkey": "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "values": {
                # "You are about to be redirected to a connection that is not secure."
                "WarnOnHTTPSToHTTPRedirect": 0,

                # "You are about to view pages over a secure connection."
                "WarnOnZoneCrossing": 0,
            },
        },
    ]

    def init_iexplore(self):
        """Sets various Internet Explorer related registry settings in case
        the user has not taken care of it already."""
        for row in self.REGKEYS:
            key_handle = OpenKey(row["key"], row["subkey"], 0, KEY_SET_VALUE)

            for key, value in row["values"].items():
                if isinstance(value, str):
                    SetValueEx(key_handle, key, 0, REG_SZ, value)
                elif isinstance(value, int):
                    SetValueEx(key_handle, key, 0, REG_DWORD, value)
                else:
                    raise CuckooPackageError("Invalid value type: %r" % value)

            CloseKey(key_handle)

    def setup_proxy(self, proxy_host):
        """Configure Internet Explorer to route all traffic through a
        proxy."""
        key = OpenKey(HKEY_CURRENT_USER, IESETTINGS, 0, KEY_SET_VALUE)
        SetValueEx(key, "MigrateProxy", 0, REG_DWORD, 1)
        SetValueEx(key, "ProxyEnable", 0, REG_DWORD, 1)
        SetValueEx(key, "ProxyHttp1.1", 0, REG_DWORD, 0)
        SetValueEx(key, "ProxyServer", 0, REG_SZ, "http://%s" % proxy_host)
        SetValueEx(key, "ProxyOverride", 0, REG_SZ, "<local>")
        CloseKey(key)

    def start(self, url):
        if "proxy" in self.options:
            self.setup_proxy(self.options["proxy"])

        self.init_iexplore()

        iexplore = self.get_path("Internet Explorer")
        return self.execute(iexplore, args=[url])
