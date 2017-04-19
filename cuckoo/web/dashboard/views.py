# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.views.decorators.http import require_safe

from cuckoo.common.config import config
from cuckoo.misc import version
from cuckoo.web.utils import render_template

@require_safe
def index(request):
    report = {
        "machinery": config("cuckoo:cuckoo:machinery"),
        "version": version,
    }
    return render_template(request, "dashboard/index.html", report=report)
