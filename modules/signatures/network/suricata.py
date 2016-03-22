# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SuricataAlert(Signature):
    name = "suricata_alert"
    description = "Raised Suricata alerts"
    severity = 3
    categories = ["network"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    def on_complete(self):
        alerts = []
        for alert in self.get_results("suricata", {}).get("alerts", []):
            if alert["signature"] not in alerts:
                alerts.append(alert["signature"])
                self.mark_ioc("suricata", alert["signature"])
        return self.has_marks()
