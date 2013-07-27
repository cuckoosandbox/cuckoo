from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "submission.views.index"),
)
