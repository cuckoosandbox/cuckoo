# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.conf.urls import url

from cuckoo.web.controllers.submission.routes import SubmissionRoutes
from cuckoo.web.controllers.submission.api import SubmissionApi

urlpatterns = [
    url(r"^$", SubmissionRoutes.submit, name="submission/index"),
    url(r"pre/(?P<submit_id>\d+)/$", SubmissionRoutes.presubmit, name="submission/pre"),
    url(r"^post/(?P<submit_id>\d+)", SubmissionRoutes.postsubmit, name="submission/post"),
    url(r"^re/(?P<task_id>\d+)/$", SubmissionRoutes.resubmit, name="submission/resubmit"),
    url(r"^(?P<task_id>\d+)/dropped/(?P<sha1>[a-f0-9]{40})/$",
        SubmissionRoutes.dropped, name="submission/dropped"),
    url(r"^api/presubmit", SubmissionApi.presubmit, name="submission/api/presubmit"),
    url(r"^api/submit", SubmissionApi.submit, name="submission/api/submit"),
    url(r"^api/filetree/$", SubmissionApi.get_files)
]
