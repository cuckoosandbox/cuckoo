# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^(?P<left_id>\d+)/$", "compare.views.left"),
    url(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/$", "compare.views.both"),
    url(r"^(?P<left_id>\d+)/(?P<right_hash>\w+)/$", "compare.views.hash"),
)
