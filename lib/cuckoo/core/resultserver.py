# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import ntpath
import struct
import socket
import logging
import time
import datetime
import SocketServer
from threading import Timer, Event, Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooResultError, CuckooOperationalError
from lib.cuckoo.common.constants import *
from lib.cuckoo.common.logtbl import table as LOGTBL
from lib.cuckoo.common.utils import create_folder, Singleton

log = logging.getLogger(__name__)

BUFSIZ = 1024 * 16


class Disconnect(Exception):
    pass


class Resultserver(SocketServer.ThreadingTCPServer, object):
    """Result server. Singleton!

    This class handles results coming back from the analysis VMs.
    """

    __metaclass__ = Singleton

    allow_reuse_address = True

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
        self.formatmap = {
            's': self.read_string,
            'S': self.read_string,
            'u': self.read_string,
            'U': self.read_string,
            'b': self.read_buffer,
            'B': self.read_buffer,
            'i': self.read_int32,
            'l': self.read_int32,
            'L': self.read_int32,
            'p': self.read_ptr,
            'P': self.read_ptr,
            'o': self.read_string,
            'O': self.read_string,
            'a': None,
            'A': None,
            'r': self.read_registry,
            'R': self.read_registry,
        }
        SocketServer.BaseRequestHandler.__init__(self, *args, **kwargs)

    def handle(self):
        ip, port = self.client_address
        sock = self.request
        log.info('new connection from: {0}:{1}'.format(ip, port))
        storagepath = self.server.build_storage_path(ip)
        if not storagepath: return
        logspath = self.create_logs_folder(storagepath)
        if not logspath: return

        # this will hold the fd to the csv file for this PID
        fd, pid, ppid, procname = (None, None, None, None)
        connect_time = datetime.datetime.now()

        try:
            while True:
                apiindex, status = struct.unpack('BB', recvall(sock, 2))
                returnval, tid, timediff = struct.unpack('III', recvall(sock, 12))

                if apiindex == 0:
                    # new process message
                    pid = self.read_int32()
                    ppid = self.read_int32()
                    modulepath = self.read_string()
                    procname = ntpath.basename(modulepath)
                    log.debug('MSG_PROCESS> PID:{0} PPID:{1} module:{2}'.format(pid, ppid, modulepath))
                    fd = open(os.path.join(logspath, str(pid) + '.csv'), 'w')

                elif apiindex == 1:
                    # new thread message
                    pid = self.read_int32()
                    log.debug('MSG_THREAD> TID:{0} PID:{1}'.format(tid, pid))

                else:
                    # actual API call
                    apiname, modulename, parseinfo = LOGTBL[apiindex]
                    formatspecifiers, argnames = parseinfo[0], parseinfo[1:]
                    arguments = []
                    for pos in range(len(formatspecifiers)):
                        fs = formatspecifiers[pos]
                        argname = argnames[pos]
                        fn = self.formatmap.get(fs, None)
                        if fn:
                            r = fn()
                            arguments.append('{0}->{1}'.format(argname, r))
                        else:
                            log.warning('No handler for format specifier {0} on apitype {1}'.format(fs,apiname))

                    current_time = connect_time + datetime.timedelta(0,0, timediff*1000)
                    timestring = logtime(current_time)
                    log.debug('MSG_CALL> TID:{0} APINAME:{1}'.format(tid, apiname))

                    print >>fd, ','.join('"{0}"'.format(i) for i in [timestring, pid,
                        procname, tid, ppid, modulename, apiname, status, returnval,
                        ] + arguments)

        except Disconnect:
            pass
        except socket.error, e:
            log.warn('socket.error: {0}'.format(e))

        if fd: fd.close()
        log.info('connection closed: {0}:{1}'.format(ip, port))

    def log_process(self, *args):
        print 'NETLOGDBG new process', args
    def log_thread(self, *args):
        print 'NETLOGDBG new thread', args
    def log_call(self, tid, *args):
        print 'NETLOGDBG call from ', tid, 'args:', args

    def read_int32(self):
        """Reads a 32bit integer from the socket."""
        return struct.unpack('I', recvall(self.request, 4))[0]

    def read_ptr(self):
        """Read a pointer from the socket."""
        value = self.read_int32()
        return '0x%08x' % value

    def read_string(self):
        """Reads an utf8 string from the socket."""
        length, maxlength = struct.unpack('II', recvall(self.request, 8))
        s = recvall(self.request, length)
        if maxlength > length: s += '... (truncated)'
        return s

    def read_buffer(self):
        """Reads a memory socket from the socket."""
        length, maxlength = struct.unpack('II', recvall(self.request, 8))
        # only return the maxlength, as we don't log the actual buffer right now
        return maxlength

    def read_registry(self):
        """Read logged registry data from the socket."""
        typ = struct.unpack('H', recvall(self.request, 2))[0]
        # do something depending on type
        return typ

    def read_list(self, fn):
        """Reads a list of _fn_ from the socket."""
        count = struct.unpack('H', recvall(self.request, 2))[0]
        ret, length = [], 0
        for x in xrange(count):
            item = fn()
            ret.append(item)
        return ret

    def create_logs_folder(self, storagepath):
        logspath = os.path.join(storagepath, "logs")
        try:
            create_folder(folder=logspath)
        except CuckooOperationalError:
            log.error("Unable to create logs folder %s" % logspath)
            return False
        return logspath


def recvall(sock, length):
    buf = ''
    while len(buf) < length:
        tmp = sock.recv(length-len(buf))
        if not tmp: raise Disconnect()
        buf += tmp

    return buf

def logtime(dt):
    t = time.strftime("%Y-%m-%d %H:%M:%S", dt.timetuple())
    s = "%s,%03d" % (t, dt.microsecond/1000)
    return s
