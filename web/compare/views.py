# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

@require_safe
def index(request):
    return render_to_response("compare/index.html",
                              context_instance=RequestContext(request))
