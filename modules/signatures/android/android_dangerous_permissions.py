# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidDangerousPermissions(Signature):
    name = "android_dangerous_permissions"
    description = "Application Asks For Dangerous Permissions (Static)"
    severity = 3
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        manifest = self.get_results("apkinfo", {}).get("manifest", {})

        for perm in manifest.get("permissions", []):
            if "dangerous" in perm["severity"] and \
                    "Unknown" not in perm["action"]:
                self.mark(permission=perm["action"])
