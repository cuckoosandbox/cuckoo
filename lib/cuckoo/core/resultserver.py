# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import shelve
import SocketServer
from threading import Timer, Event, Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.constants import *
from data.apicalls.logtbl import table as LOGTBL

log = logging.getLogger(__name__)

BUFSIZ = 1024 * 16

class disconnect(Exception):
    pass


class Resultserver(SocketServer.ThreadingTCPServer):
    """Result server. Singleton!

    This class handles results coming back from the analysis VMs.
    """

    allow_reuse_address = True
    __instance= None

    def __new__(cls, *args, **kwargs):
        if cls != type(cls.__instance):
          cls.__instance = object.__new__(cls, *args, **kwargs)
        return cls.__instance

    def __init__(self, *args, **kwargs):
        SocketServer.ThreadingTCPServer.__init__(self, *args, **kwargs)
        self.analysistasks = {}

    def add_task(self, task, machine):
        self.analysistasks[machine.ip] = (task, machine)

    def del_task(self, task, machine):
        del self.analysistasks[machine.ip]


class Resulthandler(SocketServer.BaseRequestHandler):
    """Result handler.

    This handler speaks our analysis log network protocol.
    """

    formatmap = {
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

    def handle(self):
        ip, port = self.client_address
        sock = self.request
        log.info('new connection from: {0}:{1}'.format(ip, port))
        filestorage = shelve.open('./{0}.data'.format(port))

        try:
            while True:
                timediff, apiindex = struct.unpack('IH', recvall(sock, 6))
                if apiindex == 0:
                    # new process message
                    filepath = getshortstring(sock)
                    pid, parentid = struct.unpack('II', recvall(sock, 8))
                    log.info('MSG_PROCESS> PID:{0} PARENT:{1} FILEPATH:{2}'.format(pid, parentid, filepath))

                elif apiindex == 1:
                    # new thread message
                    tid, pid = struct.unpack('II', recvall(sock, 8))
                    log.info('MSG_THREAD> TID:{0} PID:{1}'.format(tid, pid))

                else:
                    # actual API call
                    tid, status = struct.unpack('IB', recvall(sock, 5))
                    returnval = getintstring(sock)

                    apiname, parseinfo = LOGTBL[apiiindex]
                    formatspecifiers, argnames = parseinfo[0], parseinfo[1:]
                    arguments = []
                    for pos in range(len(formatspecifiers)):
                        fs = formatspecifiers[pos]
                        argname = argnames[pos]
                        fn = self.formatmap.get(fs, None)
                        if fn:
                            r = fn()
                            arguments.append('{0}={1}'.format(argname, r))
                        else:
                            log.warning('No handler for format specifier {0} on apitype {1}'.format(fs,apiname))

                    print '  TID={0} -> {1}({2}) = {3} ({4})'.format(tid, 
                        apiname, ', '.join(arguments),
                        returnval, status )

        except disconnect:
            pass
        except socket.error, e:
            log.warn('socket.error: {0}'.format(e))

        filestorage.close()
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
        length, value = read_int32(buf, offset)
        return '0x%08x' % value

    def read_string(self):
        """Reads an utf8 string from the socket."""
        length, maxlength = struct.unpack('II', recvall(self.request, 8))
        return maxlength, recvall(self.request, length)

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


def recvall(sock, length):
    buf = ''
    while len(buf) < length:
        tmp = sock.recv(length-len(buf))
        if not tmp: raise disconnect()
        buf += tmp

    return buf

def getintstring(sock):
    length = struct.unpack('I', recvall(sock, 4))
    return recvall(sock, length)
def getshortstring(sock):
    length = struct.unpack('H', recvall(sock, 4))
    return recvall(sock, length)
