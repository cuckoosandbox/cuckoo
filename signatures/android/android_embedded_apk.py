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
    minimum = "2.0"

    def on_complete(self):
        for f in self.get_apkinfo("files", []):
            if "Android application package file" in f["type"]:
                self.mark(filename=f["name"], description="Embedded APK file")
