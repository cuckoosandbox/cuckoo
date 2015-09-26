# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import patterns, url
from submission.views import Submission, SubmissionStatus


urlpatterns = patterns("",
    url(r"^$", Submission.as_view()),
    url(r"status/(?P<task_id>\d+)/$", SubmissionStatus.as_view()),
)