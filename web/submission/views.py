# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def index(request):
    if request.method == "POST":
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        options = request.POST.get("options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        tags = request.POST.get("tags", None)

        if request.POST.get("free"):
            if options:
                options += "&"
            options += "free=yes"

        if request.POST.get("process_memory"):
            if options:
                options += "&"
            options += "procmemdump=yes"

        if "sample" in request.FILES:
            # Preventive checks.
            if request.FILES["sample"].size == 0:
                return render_to_response("error.html",
                                          {"error": "You uploaded an empty file."},
                                          context_instance=RequestContext(request))
            elif request.FILES["sample"].size > settings.MAX_UPLOAD_SIZE:
                return render_to_response("error.html",
                                          {"error": "You uploaded a file that exceeds that maximum allowed upload size."},
                                          context_instance=RequestContext(request))

            path = request.FILES["sample"].temporary_file_path()

            db = Database()

            task_id = db.add_path(file_path=path,
                                  package=package,
                                  timeout=timeout,
                                  options=options,
                                  priority=priority,
                                  machine=machine,
                                  custom=custom,
                                  memory=memory,
                                  enforce_timeout=enforce_timeout,
                                  tags=tags)

            if task_id:
                return render_to_response("success.html",
                                          {"message": "The analysis task was successfully added with ID {0}.".format(task_id)},
                                          context_instance=RequestContext(request))
            else:
                return render_to_response("error.html",
                                          {"error": "Error adding task to Cuckoo's database."},
                                          context_instance=RequestContext(request))
        elif "url" in request.POST:
            url = request.POST.get("url").strip()
            if not url:
                return render_to_response("error.html",
                                          {"error": "You specified an invalid URL!"},
                                          context_instance=RequestContext(request))

            db = Database()

            task_id = db.add_url(url=url,
                                 package=package,
                                 timeout=timeout,
                                 options=options,
                                 priority=priority,
                                 machine=machine,
                                 custom=custom,
                                 memory=memory,
                                 enforce_timeout=enforce_timeout,
                                 tags=tags)

            if task_id:
                return render_to_response("success.html",
                                          {"message": "The analysis task was successfully added with ID {0}.".format(task_id)},
                                          context_instance=RequestContext(request))
            else:
                return render_to_response("error.html",
                                          {"error": "Error adding task to Cuckoo's database."},
                                          context_instance=RequestContext(request))
    else:
        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        return render_to_response("submission/index.html",
                                  {"packages": sorted(packages)},
                                  context_instance=RequestContext(request))
