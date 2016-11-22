# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from controllers.files.api import FilesApi

urlpatterns = [
    url(r"^api/view/md5/(?P<md5>\w+)/$", FilesApi.view),
    url(r"^api/view/sha256/(?P<sha256>\w+)/$", FilesApi.view),
    url(r"^api/view/id/(?P<sample_id>\d+)/$", FilesApi.view),
    url(r"^api/get/(?P<sha256>\w+)/$", FilesApi.get)
]