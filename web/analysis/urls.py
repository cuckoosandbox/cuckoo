# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url
from analysis.views import Index, Report, LatestReport, Remove, Chunk
from analysis.views import FilteredChunk, Search, Pending, PcapStream
from analysis.views import SearchBehavior


urlpatterns = [
    url(r"^$", Index.as_view()),
    url(r"^(?P<task_id>\d+)/$", Report.as_view()),
    url(r"^latest/$", LatestReport.as_view()),
    url(r"^remove/(?P<task_id>\d+)/$", Remove.as_view()),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$",
        Chunk.as_view()),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$",
        FilteredChunk.as_view()),
    url(r"^search/(?P<task_id>\d+)/$", SearchBehavior.as_view()),
    url(r"^search/$", Search.as_view()),
    url(r"^pending/$", Pending.as_view()),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$",
        PcapStream.as_view()),
]
