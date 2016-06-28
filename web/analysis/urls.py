# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from . import views
from django.conf.urls import url

urlpatterns = [
    url(r"^$", views.index),
    url(r"^(?P<task_id>\d+)/$", views.report),
    url(r"^latest/$", views.latest_report),
    url(r"^remove/(?P<task_id>\d+)/$", views.remove),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", views.chunk),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$", views.filtered_chunk),
    url(r"^search/(?P<task_id>\d+)/$", views.search_behavior),
    url(r"^search/$", views.search),
    url(r"^pending/$", views.pending),
    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", views.pcapstream),
    url(r"^moloch"
        r"/(?P<ip>[\d\.]+)?/(?P<host>[ a-zA-Z0-9-_\.]+)?"
        r"/(?P<src_ip>[a-zA-Z0-9\.]+)?/(?P<src_port>\d+|None)?"
        r"/(?P<dst_ip>[a-zA-Z0-9\.]+)?/(?P<dst_port>\d+|None)?"
        r"/(?P<sid>\d+)?",
        views.moloch),
    url(r"^(?P<task_id>\d+)/export/$", views.export_analysis),
    url(r"^import/$", views.import_analysis),
    url(r"^(?P<task_id>\d+)/reboot/$", views.reboot_analysis),
]
