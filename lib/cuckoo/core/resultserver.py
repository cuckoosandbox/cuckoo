# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket
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

    This class handles results coming back from the analysis VMs.
    """

    __metaclass__ = Singleton

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.cfg = Config()
        self.analysistasks = {}

        SocketServer.ThreadingTCPServer.__init__(self, (self.cfg.processing.ip, self.cfg.processing.port), Resulthandler, *args, **kwargs)

        self.servethread = Thread(target=self.serve_forever)
        self.servethread.setDaemon(True)
        self.servethread.start()

    def add_task(self, task, machine):
        self.analysistasks[machine.ip] = (task, machine)

    def del_task(self, task, machine):
        x = self.analysistasks.pop(machine.ip, None)
        if not x: log.warning("Resultserver did not have {0} in its task info.".format(machine.ip))

    def build_storage_path(self, ip):
        """Initialize analysis storage folder."""
        x = self.analysistasks.get(ip, None)
        if not x:
            log.critical("Resultserver unable to build storage path for connection from {0}.".format(ip))
            return False

        task, machine = x
        storagepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task.id))
        return storagepath


class Resulthandler(SocketServer.BaseRequestHandler):
    """Result handler.

    This handler speaks our analysis log network protocol.
    """

    def __init__(self, *args, **kwargs):
        self.rawlogfd = None
        self.startbuf = ''
        SocketServer.BaseRequestHandler.__init__(self, *args, **kwargs)

    def read(self, length):
        buf = ''
        while len(buf) < length:
            tmp = self.request.recv(length-len(buf))
            if not tmp: raise Disconnect()
            buf += tmp

        if self.rawlogfd: self.rawlogfd.write(buf)
        else: self.startbuf += buf
        return buf

    def handle(self):
        ip, port = self.client_address
        self.connect_time = datetime.datetime.now()        
        log.info('new connection from: {0}:{1}'.format(ip, port))

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
            log.warn('socket.error: {0}'.format(e))

        if self.logfd: self.logfd.close()
        if self.rawlogfd: self.rawlogfd.close()
        log.info('connection closed: {0}:{1}'.format(ip, port))

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        log.debug('log_process> time:{4} pid:{0} ppid:{1} module:{2} file:{3}'.format(pid, ppid, modulepath, procname, timestring))
        self.logfd = open(os.path.join(self.logspath, str(pid) + '.csv'), 'w')
        self.rawlogfd = open(os.path.join(self.logspath, str(pid) + '.raw'), 'w')
        self.rawlogfd.write(self.startbuf)
        self.pid, self.ppid, self.procname = pid, ppid, procname

    def log_thread(self, context, pid):
        log.debug('log_thread> tid:{0} pid:{1}'.format(context[3], pid))

    def log_call(self, context, apiname, modulename, arguments):
        apiindex, status, returnval, tid, timediff = context

        log.debug('log_call> tid:{0} apiname:{1}'.format(tid, apiname))

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

