# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url
from analysis.views import Index, Report, LatestReport, Remove, Chunk
from analysis.views import FilteredChunk, Search, Pending, PcapStream
from analysis.views import SearchBehavior


urlpatterns = [
    url(r"^$", Index.as_view(), name='analysis.index'),
    url(r"^(?P<task_id>\d+)/$", Report.as_view(), name='analysis.report'),
    url(r"^latest/$", LatestReport.as_view(), name='analysis.latest_report'),
    url(r"^remove/(?P<task_id>\d+)/$", Remove.as_view(), name='analysis.remove'),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$",
        Chunk.as_view(), name='analysis.chunk'),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$",
        FilteredChunk.as_view(), name='analysis.filtered_chunk'),
    url(r"^search/(?P<task_id>\d+)/$", SearchBehavior.as_view(), name='analysis.search_behavior'),
    url(r"^search/$", Search.as_view(), name='analysis.search'),
    url(r"^pending/$", Pending.as_view(), name='analysis.pending'),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$",
        PcapStream.as_view(), name='analysis.pcap_stream'),
]
