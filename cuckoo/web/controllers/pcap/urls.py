# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from cuckoo.web.controllers.pcap.api import PcapApi

urlpatterns = [
    url(r"^api/get/(?P<task_id>\d+)/$", PcapApi.get)
]
