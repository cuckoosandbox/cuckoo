from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^$', 'analysis.views.index'),
    url(r'^(?P<task_id>\d+)/$', 'analysis.views.report'),
    url(r'^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$', 'analysis.views.chunk'),
)
