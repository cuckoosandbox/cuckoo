# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from . import views
from django.conf.urls import url

urlpatterns = [
    url(r"^$", views.index),
    url(r"status/(?P<task_id>\d+)/$", views.status),
    url(r"^(?P<task_id>\d+)/$", views.resubmit),
    url(r"^(?P<task_id>\d+)/dropped/(?P<sha1>[a-f0-9]{40})/$", views.submit_dropped),
]
