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
            nc.send(tmp)
            tmp = infd.read(BUFSIZE)

        infd.close()
        nc.close()
    except Exception as e:
        log.error("Exception uploading file to host: %s", e)

class NetlogConnection(object):
    def __init__(self, proto=""):
        config = Config(cfg="analysis.conf")
        self.hostip, self.hostport = config.ip, config.port
        self.sock, self.file = None, None
        self.proto = proto

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.hostip, self.hostport))
            s.sendall(self.proto)
        except Exception as e:
            # Inception.
            log.error("Exception connecting logging handler: %s", e)
        else:
            self.sock = s
            self.file = s.makefile()

    def send(self, data, retry=True):
        try:
            self.sock.sendall(data)
        except socket.error:
            self.connect()
            if retry:
                self.send(data, retry=False)
        except:
            log.debug("Could not send to remote Netlog!")

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except socket.error:
            pass

class NetlogFile(NetlogConnection):
    def __init__(self, filepath):
        self.filepath = filepath
        NetlogConnection.__init__(self, proto="FILE\n{0}\n".format(self.filepath))
        self.connect()

class NetlogHandler(logging.Handler, NetlogConnection):
    def __init__(self):
        logging.Handler.__init__(self)
        NetlogConnection.__init__(self, proto="LOG\n")
        self.connect()

    def emit(self, record):
        msg = self.format(record)
        self.send("{0}\n".format(msg))
