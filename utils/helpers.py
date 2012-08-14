#!/usr/bin/env python
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib
import tempfile
import fcntl

from SocketServer import ThreadingTCPServer
from SimpleXMLRPCServer import SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler

from lib.cuckoo.core.database import Database

# This directory will be created in $tmppath (see store_and_submit)
TMPSUBDIR = "cuckoo-web"
BUFSIZE = 1024

# helper fn used by web.py and master.py for submitting a task from a file-like object
def store_and_submit_fileobj(fobj, filename, package="", options="", 
    timeout=0, priority=1, machine="", platform="", tmpsubdir=TMPSUBDIR):

    # Do everything in tmppath/TMPSUBDIR
    tmppath = tempfile.gettempdir()
    targetpath = os.path.join(tmppath, TMPSUBDIR)
    if not os.path.exists(targetpath): os.mkdir(targetpath)

    # Upload will be stored in a tmpdir with the original name
    tmpdir = tempfile.mkdtemp(prefix="upload_", dir=targetpath)
    tmpf = open(os.path.join(tmpdir, filename), "wb")
    t = fobj.read(BUFSIZE)

    # While reading from client also compute md5hash
    md5h = hashlib.md5()
    while t:
        md5h.update(t)
        tmpf.write(t)
        t = fobj.read(BUFSIZE)

    tmpf.close()

    # Submit task to cuckoo db
    db = Database()
    task_id = db.add(file_path=tmpf.name.decode('utf8'),
                     md5=md5h.hexdigest(),
                     package=package,
                     timeout=timeout,
                     options=options,
                     priority=priority,
                     machine=machine,
                     platform=platform)

    return task_id


# basically same as SimpleXMLRPCServer, but using ThreadedTCPServer
# see SimpleXMLRPCServer definition in stdlib
class ThreadedXMLRPCServer(ThreadingTCPServer, SimpleXMLRPCDispatcher):
    allow_reuse_address = True
    _send_traceback_header = False
    daemon_threads = True

    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=True, allow_none=False, encoding=None, bind_and_activate=True):
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)
        ThreadingTCPServer.__init__(self, addr, requestHandler, bind_and_activate)

        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)
