# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from . import views
from django.conf.urls import url

urlpatterns = [
    url(r"^$". views.rdp, name="RDP")
]
