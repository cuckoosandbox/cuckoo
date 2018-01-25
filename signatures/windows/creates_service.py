# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesService(Signature):
    name = "creates_service"
    description = "Creates a service"
    severity = 2
    categories = ["service", "persistence"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.services = []
        self.startedservices = []

    def on_call(self, call, process):
        service_name = call["arguments"].get("service_name", "").lower()
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            self.services.append(service_name)
            self.mark_call()

        elif call["api"] == "StartServiceA" or call["api"] == "StartServiceW":
            self.startedservices.append(service_name)

    def on_complete(self):
        for service in self.services:
            if service not in self.startedservices:
                self.description = "Created a service where a service was also not started"
                self.severity = 3

        return self.has_marks()
