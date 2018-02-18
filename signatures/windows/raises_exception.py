# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RaisesException(Signature):
    name = "raises_exception"
    description = "One or more processes crashed"
    severity = 1
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "__exception__",

    exception_codes = {
        "0xc0000139":
            "Windows was unable to start this executable as it is importing "
            "functions from DLLs that do not exist on this Operating System "
            "(e.g., this binary only runs on Windows 7 and your Virtual "
            "Machine is running Windows XP)",
        "0xc0000135":
            "Windows was unable to start this executable as it is importing "
            "DLLs that do not exist on this Operating System (e.g., this "
            "binary only runs on Windows 7 and your Virtual Machine is "
            "running Windows XP)",
    }

    def on_call(self, call, process):
        """Prettify the display of the call in the Signature."""
        call["raw"] = "stacktrace",
        call["arguments"]["stacktrace"] = \
            "\n".join(call["arguments"]["stacktrace"])

        exception_code = call["arguments"]["exception"]["exception_code"]
        if exception_code in self.exception_codes:
            self.severity = 5
            self.description = self.exception_codes[exception_code]
        else:
            # There's no point in keeping track of the API call for the
            # exception documented above.
            self.mark_call()

        return True
