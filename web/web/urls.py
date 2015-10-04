# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import include, url
from analysis.views import File, FullMemoryDumpFile
from django.contrib import admin
from django.contrib.auth.views import login


urlpatterns = [
    url(r"^$", include("dashboard.urls")),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/login/', login, {'template_name': 'admin/login.html'}),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^compare/", include("compare.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", File.as_view()),
    url(r"^full_memory/(?P<analysis_number>\w+)/$",
        FullMemoryDumpFile.as_view()),
    url(r"^dashboard/", include("dashboard.urls")),
]