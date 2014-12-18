# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidEmbeddedApk(Signature):
    name = "android_embedded_apk"
    description = "Application Contains a Secondary APK File (Static)"
    severity = 4
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "0.5"

    def run(self):
        try:
            for file in self.results["apkinfo"]["files"]:
                if ("Android application package file" in file["type"] ):
                    return True
            return False
        except:
            return False