# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from _winreg import HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

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
            "Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl",
            {
                "FEATURE_LOCALMACHINE_LOCKDOWN": {
                    # "To help protect your security, Internet Explorer has
                    # restricted this webpage from running scripts or ActiveX
                    # controls that could access your computer. Click here for
                    # options..."
                    "iexplore.exe": 0,
                },
                "FEATURE_RESTRICT_FILEDOWNLOAD": {
                    # "To help protect your security, Windows Internet
                    # Explorer blocked this site from downloading files to
                    # your computer. Click here for more options..."
                    "iexplore.exe": 0,
                },
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

    def start(self, target):
        if "proxy" in self.options:
            self.setup_proxy(self.options["proxy"])

        # If it's a HTML file, force an extension, or otherwise Internet
        # Explorer will open it as a text file or something else non-html.
        if os.path.exists(target) and not target.endswith((".htm", ".html")):
            os.rename(target, target + ".html")
            target += ".html"
            log.info("Submitted file is missing extension, adding .html")

        iexplore = self.get_path("Internet Explorer")
        return self.execute(
            iexplore, args=[target], maximize=True, mode="iexplore"
        )
