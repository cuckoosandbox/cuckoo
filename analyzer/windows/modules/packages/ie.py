# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from _winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER

from lib.common.abstracts import Package

class IE(Package):
    """Internet Explorer analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    REGKEYS = [
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Internet Explorer\\Main",
            {
                # "Would you like Internet Explorer as default browser?"
                "Check_Associations": "no",

                # "Set Up Windows Internet Explorer 8"
                "DisableFirstRunCustomize": 1,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Internet Explorer\\Security",
            {
                "Safety Warning Level": "Low",
                "Sending_Security": "Low",
                "Viewing_Security": "Low",
            },
        ],
        [
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Internet Explorer\\Main",
            {
                # Disable Security Settings Check.
                "DisableSecuritySettingsCheck": 1,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            {
                # "You are about to be redirected to a connection that is not secure."
                "WarnOnHTTPSToHTTPRedirect": 0,

                # "You are about to view pages over a secure connection."
                "WarnOnZoneCrossing": 0,
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Internet Explorer\\Document Windows",
            {
                # Maximize the window by default.
                "Maximized": "yes",
            },
        ],
        [
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Internet Explorer\\Download",
            {
                # "Internet Explorer - Security Warning"
                # "The publisher could not be verified."
                "CheckExeSignatures": "no",
            },
        ],
    ]

    def setup_proxy(self, proxy_host):
        """Configure Internet Explorer to route all traffic through a
        proxy."""
        self.init_regkeys([[
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            {
                "MigrateProxy": 1,
                "ProxyEnable": 1,
                "ProxyHttp1.1": 0,
                "ProxyServer": "http://%s" % proxy_host,
                "ProxyOverride": "<local>",
            },
        ]])

    def start(self, url):
        if "proxy" in self.options:
            self.setup_proxy(self.options["proxy"])

        iexplore = self.get_path("Internet Explorer")
        return self.execute(iexplore, args=[url])
