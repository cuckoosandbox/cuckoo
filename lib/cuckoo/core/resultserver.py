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

    def handle(self):
        ip, port = self.client_address
        sock = self.request
        log.info('new connection from: {0}:{1}'.format(ip, port))
        filestorage = shelve.open('./{0}.data'.format(port))

        try:
            while True:
                timediff, apiindex = struct.unpack('IB', recvall(sock, 5))
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
                    argc = struct.unpack('B', recvall(sock, 1))
                    arguments = []

                    for i in range(argc):
                        arg = {}
                        arg['truncated'] = struct.unpack('B', recvall(sock, 1))
                        argdata = getintstring(sock)
                        arg['name'], arg['value'] = argdata.split('=', 1)

                    print '  TID={0} -> {1}({2}) = {3} ({4})'.format(tid, 
                        apiindex, ', '.join('{0}={1}'.format(x['name'], x['value']) for x in arguments),
                        returnval, status )

        except disconnect:
            pass
        except socket.error, e:
            log.warn('socket.error: {0}'.format(e))

        filestorage.close()
        log.info('connection closed: {0}:{1}'.format(ip, port))


def recvall(sock, length):
    buf = ''
    while len(buf) < length:
        tmp = sock.recv(length-len(buf))
        if not tmp: raise disconnect()
        buf += tmp

    return buf
