# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from cuckoo.web.controllers.cuckoo.api import CuckooApi

urlpatterns = [
    url(r"^api/status", CuckooApi.status),
    url(r"^api/vpn/status", CuckooApi.vpn_status)
]
