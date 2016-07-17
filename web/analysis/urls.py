# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from . import views
from django.conf.urls import url
from django.views.generic import RedirectView

from controllers.analysis.routes import AnalysisRoutes
from controllers.analysis.api import AnalysisApi
from controllers.analysis.export.api import ExportApi
from controllers.analysis.feedback.api import FeedbackApi

urlpatterns = [
    url(r"^$", AnalysisRoutes.recent, name='analysis/recent'),
    url(r"^(?P<task_id>\d+)/$", AnalysisRoutes.redirect_default, name='analysis/redirect_default'),
    url(r"^(?P<task_id>\d+)/export/$", AnalysisRoutes.export, name='analysis/export'),
    url(r"^(?P<task_id>\d+)/(?P<page>\w+)/$", AnalysisRoutes.detail, name='analysis'),
    url(r"^(?P<task_id>\d+)/(?P<page>\w+)/$", AnalysisRoutes.detail, name='api'),
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
    url(r"^api/recent/$", AnalysisApi.recent),
    url(r"^api/export_estimate_size/$", ExportApi.export_estimate_size),
    url(r"^api/export_get_files/$", ExportApi.get_files),
    url(r"^api/feedback_send/$", FeedbackApi.send),
]
