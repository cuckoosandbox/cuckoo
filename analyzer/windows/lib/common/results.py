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
        config = Config(cfg="analysis.conf")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((config.ip, config.port))
        s.send("FILE\n{0}\n".format(dump_path))
        infd = open(file_path, "rb")
        tmp = infd.read(BUFSIZE)
        while tmp:
            s.sendall(tmp)
            tmp = infd.read(BUFSIZE)

        infd.close()
        s.close()
    except Exception as e:
        logging.error("Exception uploading file to host: {0}".format(e))
        return None


class NetlogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        config = Config(cfg="analysis.conf")
        self.hostip, self.hostport = config.ip, config.port
        self.sock = self._open()

    def _open(self):
        print 'OPEN called', self.hostip, self.hostport
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.hostip, self.hostport))
            s.sendall("LOG\n")
        except Exception as e:
            print "Exception connecting logging handler: {0}".format(e)

        return s

    def emit(self, record, retry=True):
        print 'TRYING TO EMIT', retry, record
        try:
            msg = self.format(record)
            self.sock.sendall("{0}\n".format(msg))
        except socket.error:
            self.sock = self._open()
            if retry:
                self.emit(record, retry=False)
