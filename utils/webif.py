#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import logging
import tempfile
import hashlib
import sqlite3

logging.basicConfig()
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../"))

from lib.bottle import route, run, static_file, redirect, request
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database

from mako.template import Template
from mako.lookup import TemplateLookup

# this directory will be created in $tmppath (see store_and_submit)
TMPSUBDIR = 'cuckoowebif'
BUFSIZE = 1024

class WebifException(Exception):
    pass

# templates directory
lookup = TemplateLookup(directories=[os.path.join(CUCKOO_ROOT, "data", "html", "webif")],
            output_encoding='utf-8',
            encoding_errors='replace',
            strict_undefined=False)

def store_and_submit_fileobj(fobj, filename, package='', options='', timeout=120, priority=1, machine=None, platform=None):
    # do everything in tmppath/TMPSUBDIR
    tmppath = tempfile.gettempdir()
    targetpath = os.path.join(tmppath, TMPSUBDIR)
    if not os.path.exists(targetpath): os.mkdir(targetpath)

    # upload will be stored in a tmpdir with the original name
    tmpdir = tempfile.mkdtemp(prefix='upload_', dir=targetpath)
    tmpf = open(os.path.join(tmpdir, filename), 'wb')
    t = fobj.read(BUFSIZE)

    # while reading from client also compute md5hash
    md5h = hashlib.md5()
    while t:
        md5h.update(t)
        tmpf.write(t)
        t = fobj.read(BUFSIZE)

    tmpf.close()

    # submit task to cuckoo db
    db = Database()
    task_id = db.add(file_path=tmpf.name,
                     md5=md5h.hexdigest(),
                     package=package,
                     timeout=timeout,
                     options=options,
                     priority=priority,
                     machine=machine,
                     platform=platform)

    return task_id

@route('/')
def index():
    context = {}
    template = lookup.get_template("submit.html")
    return template.render(**context)

@route('/browse')
def browse():
    db = Database()
    context = {}

    try:
        db.cursor.execute("SELECT * FROM tasks " \
                            "ORDER BY status, priority, added_on;")
    except sqlite3.OperationalError as e:
        context['error'] = 'Could not load tasks from database.'
        return template.render(**context)

    rows = db.cursor.fetchall()

    #[{'status': 0, 'machine': None, 'completed_on': None, 'package': None, 'lock': 1, 
    #'custom': None, 'priority': None, 'platform': None, 'options': None, 'timeout': None, 
    #'id': 1, 'file_path': u'/home/rep/Documents/taiwan12/honeynet/demo/karonzo/Open.exe', 
    #'added_on': u'2012-06-27 16:07:54', 'md5': u'1cfbccca2a84d0ee450a3f4036fd6fe3'}]

    template = lookup.get_template("browse.html")
    return template.render(os=os, rows=rows, **context)

@route('/static/<filename:path>')
def server_static(filename):
    return static_file(filename, root=os.path.join(CUCKOO_ROOT, "data", "html"))

# handle upload form
@route('/submit', method='POST')
def submit():
    context = {}
    errors = False

    # optional, can be empty
    package  = request.forms.get('package', '')
    options  = request.forms.get('options', '')
    priority = request.forms.get('priority', 1)
    timeout  = request.forms.get('timeout', 120)
    data = request.files.file

    # convert timeout
    if timeout != '':
        try: timeout = int(timeout)
        except:
            context['error_timeout'] = 'Needs to be a number'
            errors = True

    # convert priority
    try: priority = int(priority)
    except:
        context['error_priority'] = 'Needs to be a number'
        errors = True

    # file mandatory
    if data == None or data == '':
        context['error_file'] = 'Mandatory'
        errors = True

    # on errors, tell user
    if errors:
        template = lookup.get_template("submit.html")
        return template.render(timeout=timeout, priority=priority, options=options, package=package, **context)
    
    # finally real store and submit
    taskid = store_and_submit_fileobj(data.file,data.filename, timeout=timeout, priority=priority, options=options, package=package)

    # show result
    template = lookup.get_template("success.html")
    return template.render(taskid=taskid, submitfile=data.filename)

if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True, reloader=True)

