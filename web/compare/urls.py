# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url
from compare.views import Left, Hash, Both


urlpatterns = [
    url(r"^(?P<left_id>\d+)/$", Left.as_view(), name='compare.index'),
    url(r"^(?P<left_id>\d+)/(?P<right_id>\d+)/$",
        Both.as_view(),
        name='compare.both'),
    url(r"^(?P<left_id>\d+)/(?P<right_hash>\w+)/$",
        Hash.as_view(),
        name='compare.hash'),
]
