# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from . import views
from django.conf.urls import url

from controllers.analysis.routes import AnalysisRoutes
from controllers.analysis.compare.routes import AnalysisCompareRoutes
from controllers.analysis.api import AnalysisApi
from controllers.analysis.export.api import ExportApi
from controllers.analysis.feedback.api import FeedbackApi
from controllers.analysis.network.api import AnalysisNetworkApi

urlpatterns = [
    url(r"^$", AnalysisRoutes.recent, name="analysis/recent"),
    url(r"^(?P<task_id>\d+)/$", AnalysisRoutes.redirect_default, name="analysis/redirect_default"),
    url(r"^(?P<task_id>\d+)/export/$", AnalysisRoutes.export, name="analysis/export"),
    url(r"^(?P<task_id>\d+)/reboot/$", AnalysisRoutes.reboot, name="analysis/reboot"),
    url(r"^(?P<task_id>\d+)/compare/$", AnalysisCompareRoutes.left, name="analysis/compare/left"),
    url(r"^(?P<task_id>\d+)/compare/(?P<compare_with_task_id>\d+)/$", AnalysisCompareRoutes.both, name="analysis/compare/both"),
    url(r"^(?P<task_id>\d+)/compare/(?P<compare_with_hash>\w+)/$", AnalysisCompareRoutes.hash, name="analysis/compare/hash"),
    url(r"^(?P<task_id>\d+)/(?P<page>\w+)/$", AnalysisRoutes.detail, name="analysis"),
    url(r"^(?P<task_id>\d+)/(?P<page>\w+)/$", AnalysisRoutes.detail, name="api"),
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
    url(r"^import/$", views.import_analysis),
    url(r"^api/tasks/list/$", AnalysisApi.tasks_list),
    url(r"^api/tasks/info/$", AnalysisApi.tasks_info),
    url(r"^api/tasks/recent/$", AnalysisApi.tasks_recent),
    url(r"^api/tasks/stats/$", AnalysisApi.tasks_stats),
    url(r"^api/tasks/delete/$", AnalysisApi.task_delete),
    url(r"^api/task/info/(?P<task_id>\d+)/$", AnalysisApi.task_info),
    url(r"^api/task/reschedule/(?P<task_id>\d+)/(?P<priority>\d+)/$", AnalysisApi.tasks_reschedule),
    url(r"^api/task/report/(?P<task_id>\d+)/$", AnalysisApi.task_report),
    url(r"^api/task/report/(?P<task_id>\d+)/(?P<report_format>\w+)/$", AnalysisApi.task_report),
    url(r"^api/task/rereport/(?P<task_id>\d+)/$", AnalysisApi.task_rereport),
    url(r"^api/task/screenshots/(?P<task_id>\d+)/$", AnalysisApi.task_screenshots),
    url(r"^api/task/screenshots/(?P<task_id>\d+)/(?P<screenshot>\w+)/$", AnalysisApi.task_screenshots),
    url(r"^api/task/export_estimate_size/$", ExportApi.export_estimate_size),
    url(r"^api/task/export_get_files/$", ExportApi.get_files),
    url(r"^api/task/feedback_send/$", FeedbackApi.send),
    url(r"^api/task/behavior_get_processes/$", AnalysisApi.behavior_get_processes),
    url(r"^api/task/behavior_get_watcher/$", AnalysisApi.behavior_get_watcher),
    url(r"^api/task/behavior_get_watchers/$", AnalysisApi.behavior_get_watchers),
    url(r"^api/task/network_http_response_data/$", AnalysisNetworkApi.http_response_data),
]
