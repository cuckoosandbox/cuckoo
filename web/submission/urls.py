# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "submission.views.index"),
    url(r"status/(?P<task_id>\d+)/$", "submission.views.status"),
    url(r"^(?P<task_id>\d+)/$", "submission.views.resubmit"),
    url(r"^(?P<task_id>\d+)/dropped/(?P<sha1>[a-f0-9]{40})/$", "submission.views.submit_dropped"),
)
