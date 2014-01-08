# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, include, url

urlpatterns = patterns("",
    url(r"^$", "dashboard.views.index"),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.file"),
    url(r"^dashboard/", include("dashboard.urls")),
)