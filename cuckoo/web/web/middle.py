# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.shortcuts import redirect
from ipaddress import ip_network, ip_address

from cuckoo.common.config import config
from cuckoo.misc import version

class CuckooAuthentication(object):
    def process_request(self, request):
        if request.path.startswith(("/secret/", "/static/")):
            return
        # If no web_secret has been initialized, ignore this functionality.
        if not config("cuckoo:cuckoo:web_secret"):
            return
        if not request.session.get("auth"):
            return redirect("/secret/")

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

class CuckooFileDownloadAuthentication(object):
    def process_request(self, request):
        if not request.path.startswith(("/file/sample/", "/file/dropped/")):
            return

        #if no ALLOWED_FILEDOWNLOAD_SUBNETS in web local_settings, ignore this
        try:
            from settings import ALLOWED_FILEDOWNLOAD_SUBNETS
        except ImportError:
            return

        ip = request.META.get("REMOTE_ADDR")
        isallowed = False
        if ip:
            for network in ALLOWED_FILEDOWNLOAD_SUBNETS.split(","):
                network = ip_network(unicode(network), strict=False)
                if ip_address(unicode(ip)) in network:
                    isallowed = True
                    return

        if not isallowed and not request.session.get("auth"):
            return redirect("/secret/")
