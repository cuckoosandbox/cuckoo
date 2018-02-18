# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousJavascript(Signature):
    name = "js_suspicious"
    description = "Suspicious Javascript actions"
    severity = 3
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "COleScript_Compile",

    js_re = [
        "eval\\(\\s*eval\\(",
        "eval\\(\\s*\\['\"]\\s*String\\.fromCharCode",
        "^\\s*String\\.fromCharCode\\((?:[0-9a-fA-F,\\s]+)\\)\\s*$",
        "\\s*document\\.location\\.href\\s*=\\s*['\"].*['\"];$",
        "malware\\.dontneedcoffee\\.com",
    ]

    def on_call(self, call, process):
        for regex in self.js_re:
            if re.search(regex, call["arguments"]["script"], re.S):
                self.mark_call()
                break

        return self.has_marks()

class AntiAnalysisJavascript(Signature):
    name = "js_anti_analysis"
    description = "Tries to detect analysis programs from within the browser"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    on_call_dispatch = True

    filter_apinames = "ActiveXObjectFncObj_Construct", "CImgElement_put_src"

    activex_objnames = [
        "Kaspersky.IeVirtualKeyboardPlugin.JavascriptApi",
        "Kaspersky.IeVirtualKeyboardPlugin.JavascriptApi.1",
        "Kaspersky.IeVirtualKeyboardPlugin.JavascriptApi.4_5_0.1",
    ]

    image_blacklisted = [
        "Fiddler2",
        "VMware",
        "Oracle",
        "Parallels",
        "Malwarebytes",
        "Trend Micro",
        "Kaspersky Lab",
    ]

    def on_call_ActiveXObjectFncObj_Construct(self, call, process):
        if call["arguments"]["objname"] in self.activex_objnames:
            self.mark_call()
            return True

    def on_call_CImgElement_put_src(self, call, process):
        src = call["arguments"]["src"].lower()
        if not src.startswith("res://"):
            return

        for blacklist in self.image_blacklisted:
            if blacklist.lower() in src:
                self.mark_call()
                return True
