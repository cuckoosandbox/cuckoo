from django.conf.urls import patterns, include, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.file"),
)