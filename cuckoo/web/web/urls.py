# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.views.static import serve
from django.conf import settings
from django.conf.urls import include, url

import dashboard.views
import analysis.views
import web.errors

urlpatterns = [
    url(r"^$", dashboard.views.index),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w*)/$", analysis.views.file),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w*)/(?P<fetch>\w+)/$", analysis.views.file),
    url(r"^full_memory/(?P<analysis_number>\w+)/$", analysis.views.full_memory_dump_file),
    url(r"^dashboard/", include("dashboard.urls")),
    url(r"^static/(?P<path>.*)$", serve, {"document_root": settings.STATICFILES_DIRS[0]}),
    url(r"^files/", include("controllers.files.urls")),
    url(r"^pcap/", include("controllers.pcap.urls")),
    url(r"^machines/", include("controllers.pcap.urls")),
    url(r"^cuckoo/", include("controllers.cuckoo.urls")),
]

handler404 = web.errors.handler404
handler500 = web.errors.handler500
