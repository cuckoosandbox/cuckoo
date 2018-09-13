# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods

from cuckoo.common.config import config
from cuckoo.web.utils import render_template

@require_http_methods(["GET", "POST"])
def secret(request):
    if request.method == "GET":
        return render_template(request, "secret.html")

    if request.POST.get("secret") == config("cuckoo:cuckoo:web_secret"):
        request.session["auth"] = True
        return redirect("/")

    return render_template(request, "secret.html", fail=True)
