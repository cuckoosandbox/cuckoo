#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import argparse
from datetime import datetime, timedelta

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

def parse_tasks(rows):
    """Parse tasks from DB and prepare them to be shown in the output table.
    @params rows: data from DB
    @return: task list
    """
    tasks = []
    if rows:
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
    return tasks

def get_pagination_limit(new_limit):
    """Defines the right pagination limit and sets cookies accordingly.
    @params new_limit: new pagination limit
    """
    default_limit = 50
    
    limit_cookie = request.get_cookie("pagination_limit")
    logging.info("Got cookie: {0}".format(limit_cookie))
    
    cookie_expires = time.mktime((datetime.now() + timedelta(days=365)).timetuple())
    
    if new_limit <= 0:
        if limit_cookie:
            try:
                limit = int(limit_cookie)
                logging.info("Using limit from cookie: {0}".format(limit))
                response.set_cookie("pagination_limit", str(limit), path="/", expires=cookie_expires)
            except Exception as e:
                logging.error("Cookie: {0}, exception: {1}".format(limit_cookie, e))
                limit = default_limit
        else:
            limit = default_limit
            logging.info("Using default limit: {0}".format(limit))
    else:
        limit = new_limit
        logging.info("Setting new limit: {0}".format(limit))
        response.set_cookie("pagination_limit", str(limit), path="/", expires=cookie_expires)
    
    return limit

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

@route("/")
def index():
    context = {}
    template = env.get_template("submit.html")
    return template.render({"context" : context, "machines" : [m.name for m in db.list_machines()]})

@route("/browse")
def browse():
    rows = db.list_tasks()

    tasks = parse_tasks(rows)

    template = env.get_template("browse.html")

    return template.render({"rows" : tasks, "os" : os})

@route("/browse/page")
@route("/browse/page/")
@route("/browse/page/<page_id:int>")
@route("/browse/page/<page_id:int>/")
@route("/browse/page/<page_id:int>/<new_limit:int>")
def browse_page(page_id=1, new_limit=-1):
    if page_id < 1:
        page_id = 1
    
    limit = get_pagination_limit(new_limit)
    
    tot_results = db.count_tasks()
    tot_pages = (tot_results / limit) + ((tot_results % limit) and 1 or 0) # Add 1 to tot_pages
                                                                           # if there's some remainder
    # Check that the user doesn't require an impossible pagination
    if page_id > tot_pages:
        page_id = tot_pages
    
    offset = (page_id - 1) * limit
    rows = db.list_tasks(limit=limit, offset=offset)
    
    tasks = parse_tasks(rows)
    
    if tot_results:
        pagination_start = offset + 1
    else:
        pagination_start = 0
    pagination_end = offset + len(rows)
    
    pagination = {
        "start" : pagination_start,
        "end" : pagination_end,
        "limit" : limit,
        "page_id" : page_id,
        "tot_results" : tot_results,
        "tot_pages" : tot_pages
    }
    
    template = env.get_template("browse.html")
    
    return template.render({"rows": tasks, "os" : os, "pagination" : pagination})

@route("/static/<filename:path>")
def server_static(filename):
    return static_file(filename, root=os.path.join(CUCKOO_ROOT, "data", "html"))

@route("/submit", method="POST")
def submit():
    context = {}
    errors = False

    package  = request.forms.get("package", "")
    options  = request.forms.get("options", "")
    priority = request.forms.get("priority", 1)
    timeout  = request.forms.get("timeout", 0)
    machine  = request.forms.get("machine", "")
    memory  = request.forms.get("memory", "")
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
                                "context" : context,
                                "machine" : machine,
                                "memory" : memory})

    temp_file_path = store_temp_file(data.file.read(), data.filename)

    task_id = db.add_path(file_path=temp_file_path,
                          timeout=timeout,
                          priority=priority,
                          options=options,
                          package=package,
                          machine=machine,
                          memory=memory)

    if task_id:
        template = env.get_template("success.html")
        return template.render({"taskid" : task_id,
                            "submitfile" : data.filename.decode("utf-8")})
    else:
        template = env.get_template("error.html")
        return template.render({"error" : "The server encountered an internal error while submitting {0}".format(data.filename.decode("utf-8"))})

@route("/view/<task_id>/download")
def downlaod_report(task_id):
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.html")

    if not os.path.exists(report_path):
        return HTTPError(code=404, output="Report not found")

    response.content_type = "text/html"
    response.set_header("Content-Disposition", "attachment; filename=cuckoo_task_{0}.html".format(task_id))

    return open(report_path, "rb").read()

@route("/view/<task_id>")
def view(task_id):
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.html")

    if not os.path.exists(report_path):
        return HTTPError(code=404, output="Report not found")

    return open(report_path, "rb").read().replace("<!-- BOTTLEREMOVEME", "").replace("BOTTLEREMOVEME --!>", "")

@route("/pcap/<task_id>")
def get_pcap(task_id):
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    pcap_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump.pcap")

    if not os.path.exists(pcap_path):
        return HTTPError(code=404, output="PCAP not found")

    response.content_type = "application/vnd.tcpdump.pcap"
    response.set_header("Content-Disposition", "attachment; filename=cuckoo_task_{0}.pcap".format(task_id))

    return open(pcap_path, "rb").read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the web server on", default="0.0.0.0", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the web server on", default=8080, action="store", required=False)
    args = parser.parse_args()

    run(host=args.host, port=args.port, reloader=True)
