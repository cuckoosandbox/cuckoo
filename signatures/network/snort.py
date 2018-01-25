# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SnortAlert(Signature):
    name = "snort_alert"
    description = "Raised Snort alerts"
    severity = 3
    categories = ["network"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        alerts = []
        for alert in self.get_results("snort", {}).get("alerts", []):
            if alert["message"] not in alerts:
                alerts.append(alert["message"])
                self.mark_ioc("snort", alert["message"])
        return self.has_marks()
