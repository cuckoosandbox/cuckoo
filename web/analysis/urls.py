# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
)
