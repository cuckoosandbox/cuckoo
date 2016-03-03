# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class SystemMetrics(Signature):
    name = "generic_metrics"
    description = "Uses GetSystemMetrics"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "2.0"

    # Evented signatures can specify filters that reduce the amount of
    # API calls that are streamed in. One can filter Process name, API
    # name/identifier and category.
    filter_processnames = ()
    filter_apinames = "GetSystemMetrics",
    filter_categories = ()

    # This is a signature template. It should be used as a skeleton for
    # creating custom signatures, therefore is disabled by default.
    # The on_call function is used in "evented" signatures.
    # These use a more efficient way of processing logged API calls.
    enabled = False

    def stop(self):
        # In the stop method one can implement any cleanup code and
        #  decide one last time if this signature matches or not.
        #  Return True in case it matches.
        return False

    # This method will be called for every logged API call by the loop
    # in the RunSignatures plugin. The return value determines the "state"
    # of this signature. True means the signature matched and False means
    # it can't match anymore. Both of which stop streaming in API calls.
    # Returning None keeps the signature active and will continue.
    def on_call(self, call, pid, tid):
        # This check would in reality not be needed as we already make use
        # of filter_apinames above.
        if call["api"] == "GetSystemMetrics":
            # Signature matched, return True.
            return True

        # continue
        return None
