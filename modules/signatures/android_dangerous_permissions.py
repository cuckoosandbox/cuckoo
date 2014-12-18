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
    minimum = "0.5"

    def run(self):
        references = []
        try:
            for perm in self.results["apkinfo"]["manifest"]["permissions"]:
                if("dangerous" in perm["severity"]):
                    if not ("Unknown" in perm["action"]):
                        references.append(perm)

            if len(references)>0:
                return True
            else:
                return False
        except:
            return False




