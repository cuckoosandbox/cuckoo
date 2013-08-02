#!/usr/bin/env python
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from os.path import isfile,isdir,join
from os import listdir
import sys
import logging
import argparse
try:
    from jinja2.loaders import FileSystemLoader
    from jinja2.environment import Environment
except ImportError:
    sys.stderr.write("ERROR: Jinja2 library is missing")
    sys.exit(1)
try:
    from bottle import route, run, static_file, redirect, request, HTTPError, hook, response
except ImportError:
    sys.stderr.write("ERROR: Bottle library is missing")
    sys.exit(1)

logging.basicConfig()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file

# Templating engine.
env = Environment()
env.loader = FileSystemLoader(os.path.join(CUCKOO_ROOT, "data", "html"))
# Global db pointer.
db = Database()

@hook("after_request")
def custom_headers():
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"

def define_modules_list(context):
    mypath = os.path.join(CUCKOO_ROOT, "analyzer")
    context["operating_system"] = [ osys for osys in listdir(mypath) if isdir(join(mypath,osys)) ]
    for osystem in context["operating_system"]:
        mypath = os.path.join(CUCKOO_ROOT, "analyzer",osystem,"modules","packages")
        context["os_modules"]=[ osystem+"_"+f.replace(".py","") for f in listdir(mypath) if isfile(join(mypath,f)) and f <> "__init__.py"   ]
    return context    

@route("/")
def index():
    context = {}
    context = define_modules_list(context)
    
    template = env.get_template("submit.html")
    return template.render({"context" : context})

@route("/browse")
def browse():
    rows = db.list_tasks()

    tasks = []
    for row in rows:
        task = {
            "id" : row.id,
            "target" : row.target,
            "category" : row.category,
            "status" : row.status,
            "added_on" : row.added_on,
            "processed" : False
        }

        if os.path.exists(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]), "reports", "report.html")):
            task["processed"] = True

        if row.category == "file":
            sample = db.view_sample(row.sample_id)
            task["md5"] = sample.md5

        tasks.append(task)

    template = env.get_template("browse.html")

    return template.render({"rows" : tasks, "os" : os})

@route("/static/<filename:path>")
def server_static(filename):
    return static_file(filename, root=os.path.join(CUCKOO_ROOT, "data", "html"))

@route("/submit", method="POST")
def submit():
    context = {}
    errors = False

    package  = request.forms.get("package", "")
    platform  = request.forms.get("platform", "")
    options  = request.forms.get("options", "")
    priority = request.forms.get("priority", 1)
    timeout  = request.forms.get("timeout", "")
    data = request.files.file

    try:
        priority = int(priority)
    except ValueError:
        context["error_toggle"] = True
        context["error_priority"] = "Needs to be a number"
        errors = True

    if data == None or data == "":
        context["error_toggle"] = True
        context["error_file"] = "Mandatory"
        errors = True

    if errors:
        template = env.get_template("submit.html")
        return template.render({"timeout" : timeout,
                                "priority" : priority,
                                "options" : options,
                                "package" : package,
                                "platform" : platform,
                                "context" : context})

    temp_file_path = store_temp_file(data.file.read(), data.filename)

    task_id= db.add_path(file_path=temp_file_path,
                         timeout=timeout,
                         priority=priority,
                         options=options,
                         package=package,
                         platform=platform)

    template = env.get_template("success.html")
    return template.render({"taskid" : task_id,
                            "submitfile" : data.filename.decode("utf-8")})

@route("/view/<task_id>")
def view(task_id):
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.html")

    if not os.path.exists(report_path):
        return HTTPError(code=404, output="Report not found")

    return open(report_path, "rb").read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the web server on", default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the web server on", default=8080, action="store", required=False)
    args = parser.parse_args()

    run(host=args.host, port=args.port, reloader=True)
