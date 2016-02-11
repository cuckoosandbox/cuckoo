# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import dashboard.views
import analysis.views

from django.conf.urls import include, url

urlpatterns = [
    url(r"^$", dashboard.views.index),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^compare/", include("compare.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", analysis.views.file),
    url(r"^full_memory/(?P<analysis_number>\w+)/$", analysis.views.full_memory_dump_file),
    url(r"^dashboard/", include("dashboard.urls")),
]