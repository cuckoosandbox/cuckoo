# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.views.decorators.http import require_safe

from cuckoo.web.utils import render_template

@require_safe
def rdp(request):
    request.extra_scripts = ['guac.js']
    return render_template(request, "rdp/index.html")
