# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import socket

from lib.core.config import Config

log = logging.getLogger(__name__)

BUFSIZE = 16 * 1024

def upload_to_host(file_path, dump_path):
    nc = infd = None
    try:
        nc = NetlogFile(dump_path)

        infd = open(file_path, "rb")
        tmp = infd.read(BUFSIZE)
        while tmp:
            nc.send(tmp)
            tmp = infd.read(BUFSIZE)
    except Exception as e:
        log.error("Exception uploading file to host: %s", e)
    finally:
        if infd:
            infd.close()
        if nc:
            nc.close()

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
        except:
            pass
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
            # We really have nowhere to log this, if the netlog connection
            # does not work, we can assume that any logging won't work either.
            # So we just fail silently.
            self.close()

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
