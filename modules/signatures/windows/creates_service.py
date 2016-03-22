# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesService(Signature):
    name = "creates_service"
    description = "Creates a service"
    severity = 2
    categories = ["service"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "CreateServiceA", "CreateServiceW"

    def on_call(self, call, process):
        self.mark_call()
        return True
