# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket
import select
import logging
import time
import datetime
import SocketServer
from threading import Timer, Event, Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooResultError, CuckooOperationalError
from lib.cuckoo.common.constants import *
from lib.cuckoo.common.utils import create_folder, Singleton, logtime
from lib.cuckoo.common.netlog import NetlogParser

log = logging.getLogger(__name__)

class Disconnect(Exception):
    pass

class Resultserver(SocketServer.ThreadingTCPServer, object):
    """Result server. Singleton!

    This class handles results coming back from the analysis machines.
    """

    __metaclass__ = Singleton

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.cfg = Config()
        self.analysistasks = {}
        self.analysishandlers = {}

        try:
            SocketServer.ThreadingTCPServer.__init__(self,
                                                     (self.cfg.resultserver.ip, self.cfg.resultserver.port),
                                                     Resulthandler,
                                                     *args,
                                                     **kwargs)
        except Exception as e:
            log.error("Unable to bind result server on %s:%s: %s",
                      self.cfg.resultserver.ip, self.cfg.resultserver.port, e)
        else:
            self.servethread = Thread(target=self.serve_forever)
            self.servethread.setDaemon(True)
            self.servethread.start()

    def add_task(self, task, machine):
        """Register a task/machine with the Resultserver."""
        self.analysistasks[machine.ip] = (task, machine)
        self.analysishandlers[task.id] = []

    def del_task(self, task, machine):
        """Delete Resultserver state and wait for pending RequestHandlers."""
        x = self.analysistasks.pop(machine.ip, None)
        if not x: log.warning("Resultserver did not have {0} in its task info.".format(machine.ip))
        handlers = self.analysishandlers.pop(task.id, None)
        for h in handlers:
            h.end_request.set()
            h.done_event.wait()

    def register_handler(self, handler):
        """Register a RequestHandler so that we can later wait for it."""
        task, machine = self.get_ctx_for_ip(handler.client_address[0])
        if not task or not machine: return False
        self.analysishandlers[task.id].append(handler)

    def get_ctx_for_ip(self, ip):
        """Return state for this ip's task."""
        x = self.analysistasks.get(ip, None)
        if not x:
            log.critical("Resultserver unable to map ip to context: {0}.".format(ip))
            return None, None

        return x

    def build_storage_path(self, ip):
        """Initialize analysis storage folder."""
        task, machine = self.get_ctx_for_ip(ip)
        if not task or not machine: return False

        storagepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task.id))
        return storagepath

class Resulthandler(SocketServer.BaseRequestHandler):
    """Result handler.

    This handler speaks our analysis log network protocol.
    """

    def setup(self):
        self.rawlogfd = None
        self.startbuf = ''
        self.end_request = Event()
        self.done_event = Event()
        self.server.register_handler(self)

    def finish(self):
        self.done_event.set()

    def wait_sock_or_end(self):
        while True:
            if self.end_request.isSet(): return False
            rs,ws,xs = select.select([self.request],[],[],1)
            if rs: return True

    def read(self, length):
        buf = ''
        while len(buf) < length:
            if not self.wait_sock_or_end(): raise Disconnect()
            tmp = self.request.recv(length-len(buf))
            if not tmp: raise Disconnect()
            buf += tmp

        if self.rawlogfd: self.rawlogfd.write(buf)
        else: self.startbuf += buf
        return buf

    def handle(self):
        ip, port = self.client_address
        self.connect_time = datetime.datetime.now()        
        log.debug("New connection from: {0}:{1}".format(ip, port))

        self.storagepath = self.server.build_storage_path(ip)
        if not self.storagepath: return
        self.logspath = self.create_logs_folder()
        if not self.logspath: return

        # netlog protocol parser
        nlp = NetlogParser(self)
        try:
            while True:
                r = nlp.read_next_message()
                if not r: break
        except Disconnect:
            pass
        except socket.error, e:
            log.debug("socket.error: {0}".format(e))

        if self.logfd: self.logfd.close()
        if self.rawlogfd: self.rawlogfd.close()
        log.debug("Connection closed: {0}:{1}".format(ip, port))

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        log.debug("New process (pid={0}, ppid={1}, name={2}, path={3})".format(pid, ppid, procname, modulepath))
        self.logfd = open(os.path.join(self.logspath, str(pid) + '.csv'), 'w')
        self.rawlogfd = open(os.path.join(self.logspath, str(pid) + '.raw'), 'w')
        self.rawlogfd.write(self.startbuf)
        self.pid, self.ppid, self.procname = pid, ppid, procname

    def log_thread(self, context, pid):
        log.debug("New thread (tid={0}, pid={1})".format(context[3], pid))

    def log_call(self, context, apiname, modulename, arguments):
        apiindex, status, returnval, tid, timediff = context

        #log.debug('log_call> tid:{0} apiname:{1}'.format(tid, apiname))

        current_time = self.connect_time + datetime.timedelta(0,0, timediff*1000)
        timestring = logtime(current_time)

        argumentstrings = ['{0}->{1}'.format(argname, r) for argname, r in arguments]

        print >>self.logfd, ','.join('"{0}"'.format(i) for i in [timestring, self.pid,
            self.procname, tid, self.ppid, modulename, apiname, status, returnval,
            ] + argumentstrings)

    def create_logs_folder(self):
        logspath = os.path.join(self.storagepath, "logs")

        try:
            create_folder(folder=logspath)
        except CuckooOperationalError:
            log.error("Unable to create logs folder %s" % logspath)
            return False

        return logspath
