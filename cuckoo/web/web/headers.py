# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.misc import version

class CuckooHeaders(object):
    """Set Cuckoo custom response headers."""

    def process_response(self, request, response):
        response["Server"] = "Machete Server"
        response["X-Cuckoo-Version"] = version
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Pragma"] = "no-cache"
        response["Cache-Control"] = "no-cache"
        response["Expires"] = "0"
        return response
