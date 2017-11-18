# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from . import views
from django.conf.urls import url

from cuckoo.web.controllers.analysis.api import AnalysisApi
from cuckoo.web.controllers.analysis.compare.routes import AnalysisCompareRoutes
from cuckoo.web.controllers.analysis.export.api import ExportApi
from cuckoo.web.controllers.analysis.network.api import AnalysisNetworkApi
from cuckoo.web.controllers.analysis.routes import AnalysisRoutes
from cuckoo.web.controllers.submission.routes import SubmissionRoutes

urlpatterns = [
    url(r"^$", AnalysisRoutes.recent, name="analysis/recent"),
    url(r"^(?P<task_id>\d+)/$", AnalysisRoutes.redirect_default, name="analysis/redirect_default"),
    url(r"^(?P<task_id>\d+)/export/$", AnalysisRoutes.export, name="analysis/export"),
    url(r"^(?P<task_id>\d+)/reboot/$", SubmissionRoutes.reboot, name="analysis/reboot"),
    url(r"^(?P<task_id>\d+)/compare/$", AnalysisCompareRoutes.left, name="analysis/compare/left"),
    url(r"^(?P<task_id>\d+)/compare/(?P<compare_with_task_id>\d+)/$", AnalysisCompareRoutes.both, name="analysis/compare/both"),
    url(r"^(?P<task_id>\d+)/compare/(?P<compare_with_hash>\w+)/$", AnalysisCompareRoutes.hash, name="analysis/compare/hash"),
    # TODO Get rid of this magic routing again as it's only complicating the URL routing.
    url(r"^(?P<task_id>\d+)/(?P<page>summary)$", AnalysisRoutes.detail, name="analysis"),
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
    url(r"^import/$", SubmissionRoutes.import_, name="analysis/import"),
    # url(r"^api/tasks/list/$", AnalysisApi.tasks_list),
    url(r"^api/tasks/info/$", AnalysisApi.tasks_info),
    url(r"^api/tasks/recent/$", AnalysisApi.tasks_recent),
    url(r"^api/tasks/stats/$", AnalysisApi.tasks_stats),
    # url(r"^api/tasks/delete/$", AnalysisApi.task_delete),
    # url(r"^api/task/info/(?P<task_id>\d+)/$", AnalysisApi.task_info),
    # url(r"^api/task/reschedule/(?P<task_id>\d+)/(?P<priority>\d+)/$", AnalysisApi.tasks_reschedule),
    # url(r"^api/task/report/(?P<task_id>\d+)/$", AnalysisApi.task_report),
    # url(r"^api/task/report/(?P<task_id>\d+)/(?P<report_format>\w+)/$", AnalysisApi.task_report),
    # url(r"^api/task/rereport/(?P<task_id>\d+)/$", AnalysisApi.task_rereport),
    # url(r"^api/task/screenshots/(?P<task_id>\d+)/$", AnalysisApi.task_screenshots),
    # url(r"^api/task/screenshots/(?P<task_id>\d+)/(?P<screenshot>\w+)/$", AnalysisApi.task_screenshots),
    url(r"^api/task/export_estimate_size/$", ExportApi.export_estimate_size),
    url(r"^api/task/export_get_files/$", ExportApi.get_files),
    url(r"^api/task/feedback_send/$", AnalysisApi.feedback_send),
    url(r"^api/task/network_http_data/$", AnalysisNetworkApi.http_data),
]
