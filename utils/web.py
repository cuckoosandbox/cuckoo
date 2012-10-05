#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
from mako.template import Template
from mako.lookup import TemplateLookup
from bottle import route, run, static_file, redirect, request, HTTPError

logging.basicConfig()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file

#from SocketServer import ThreadingTCPServer
#from SimpleXMLRPCServer import SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler
#
# basically same as SimpleXMLRPCServer, but using ThreadedTCPServer
# see SimpleXMLRPCServer definition in stdlib
#class ThreadedXMLRPCServer(ThreadingTCPServer, SimpleXMLRPCDispatcher):
#    allow_reuse_address = True
#    _send_traceback_header = False
#    daemon_threads = True
#
#    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
#                 logRequests=True, allow_none=False, encoding=None, bind_and_activate=True):
#        self.logRequests = logRequests
#
#        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)
#        ThreadingTCPServer.__init__(self, addr, requestHandler, bind_and_activate)
#
#        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
#            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
#            flags |= fcntl.FD_CLOEXEC
#            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

# Templates directory
lookup = TemplateLookup(directories=[os.path.join(CUCKOO_ROOT, "data", "html")],
                        output_encoding="utf-8",
                        encoding_errors="replace",
                        strict_undefined=False)

@route("/")
def index():
    context = {}
    template = lookup.get_template("submit.html")
    return template.render(**context)

@route("/browse")
def browse():
    db = Database()
    context = {}

    rows = db.list()
    template = lookup.get_template("browse.html")
    context["cuckoo_root"] = CUCKOO_ROOT

    return template.render(os=os, rows=rows, **context)

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
    timeout  = request.forms.get("timeout", "")
    data = request.files.file

    # Convert priority
    try:
        priority = int(priority)
    except:
        context["error_toggle"] = True
        context["error_priority"] = "Needs to be a number"
        errors = True

    # File mandatory
    if data == None or data == "":
        context["error_toggle"] = True
        context["error_file"] = "Mandatory"
        errors = True

    # On errors, tell user
    if errors:
        template = lookup.get_template("submit.html")
        return template.render(timeout=timeout, priority=priority, options=options, package=package, **context)

    temp_file_path = store_temp_file(data.file.read(), data.filename)
    db = Database()
    taskid= db.add_path(file_path=temp_file_path, timeout=timeout, priority=priority, options=options, package=package)

    template = lookup.get_template("success.html")
    return template.render(taskid=taskid, submitfile=data.filename.decode("utf8"))

@route("/view/<task_id>")
def view(task_id):
    # Check if the specified task ID is valid
    if not task_id.isdigit():
        return HTTPError(code=404, output="The specified ID is invalid")

    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.html")

    # Check if the HTML report exists
    if not os.path.exists(report_path):
        return HTTPError(code=404, output="Report not found")

    return open(report_path, "rb").read()

if __name__ == "__main__":
    run(host="0.0.0.0", port=8080, reloader=True)
