# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from cuckoo.web.controllers.files.api import FilesApi

urlpatterns = [
    url(r"^api/view/md5/(?P<md5>\w+)/$", FilesApi.view),
    url(r"^api/view/sha256/(?P<sha256>\w+)/$", FilesApi.view),
    url(r"^api/view/id/(?P<sample_id>\d+)/$", FilesApi.view),
    url(r"^api/get/(?P<sha256>\w+)/$", FilesApi.get)
]
