# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DeadHost(Signature):
    name = "dead_host"
    description = (
        "Connects to an IP address that is no longer responding to "
        "requests (legitimate services will remain up-and-running usually)"
    )
    severity = 3
    categories = ["network"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    whitelist = [
        "13.107.4.50",
    ]

    def on_complete(self):
        for ip, port in self.get_results("network", {}).get("dead_hosts", []):
            if ip not in self.whitelist:
                self.mark_ioc("dead_host", "%s:%s" % (ip, port))
                self.severity += 2

        if self.severity > 8:
            self.severity = 8

        if self.has_marks(2):
            self.description = (
                "Connects to IP addresses that are no longer responding to "
                "requests (legitimate services will remain up-and-running "
                " usually)"
            )

        return self.has_marks()
