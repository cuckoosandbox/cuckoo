# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import socket

from lib.core.config import Config

log = logging.getLogger(__name__)

BUFSIZE = 16 * 1024

def upload_to_host(file_path, dump_path):
    try:
        nc = NetlogFile(dump_path)

        infd = open(file_path, "rb")
        tmp = infd.read(BUFSIZE)
        while tmp:
            nc.sock.sendall(tmp)
            tmp = infd.read(BUFSIZE)

        infd.close()
        nc.close()
    except Exception as e:
        logging.error("Exception uploading file to host: {0}".format(e))
        return None


class NetlogConnection(object):
    def __init__(self):
        config = Config(cfg="analysis.conf")
        self.hostip, self.hostport = config.ip, config.port
        self.sock, self.file = None, None

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.hostip, self.hostport))
        except Exception as e:
            print "Exception connecting logging handler: {0}".format(e)

        self.sock = s
        self.file = s.makefile()

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except socket.error:
            pass


class NetlogFile(NetlogConnection):
    def __init__(self, filepath):
        self.filepath = filepath
        NetlogConnection.__init__(self)
        self.connect()
        self.sock.sendall("FILE\n{0}\n".format(self.filepath))


class NetlogHandler(logging.Handler, NetlogConnection):
    def __init__(self):
        logging.Handler.__init__(self)
        NetlogConnection.__init__(self)
        self.connect()
        self.sock.sendall("LOG\n")

    def emit(self, record, retry=True):
        try:
            msg = self.format(record)
            self.sock.sendall("{0}\n".format(msg))
        except socket.error:
            self.connect()
            if retry:
                self.emit(record, retry=False)
