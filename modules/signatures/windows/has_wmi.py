# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HasWMI(Signature):
    name = "has_wmi"
    description = "Executes one or more WMI queries"
    severity = 2

    def on_complete(self):
        for query in self.get_wmi_queries():
            self.mark_ioc("wmi", query)

        return self.has_marks()
