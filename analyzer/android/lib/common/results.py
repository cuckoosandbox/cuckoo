# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import socket
import time

from lib.core.config import Config

log = logging.getLogger(__name__)

BUFSIZE = 1024*1024

def upload_to_host(file_path, dump_path):
    nc = infd = None
    try:
        nc = NetlogFile(dump_path)

        infd = open(file_path, "rb")
        buf = infd.read(BUFSIZE)
        while buf:
            nc.send(buf, retry=False)
            buf = infd.read(BUFSIZE)
    except Exception as e:
        log.error("Exception uploading file %s to host: %s", file_path, e)
    finally:
        if infd:
            infd.close()
        if nc:
            nc.close()

class NetlogConnection(object):
    def __init__(self, proto=""):
        config = Config(cfg="analysis.conf")
        self.hostip, self.hostport = config.ip, config.port
        self.sock = None
        self.proto = proto

    def connect(self):
        # Try to connect as quickly as possible. Just sort of force it to
        # connect with a short timeout.
        while not self.sock:
            try:
                s = socket.create_connection((self.hostip, self.hostport), 0.1)
                s.sendall(self.proto)
            except socket.error:
                time.sleep(0.1)
                continue

            self.sock = s

    def send(self, data, retry=True):
        if not self.sock:
            self.connect()

        try:
            self.sock.sendall(data)
        except socket.error as e:
            if retry:
                self.connect()
                self.send(data, retry=False)
            else:
                raise
        except Exception as e:
            log.error("Unhandled exception in NetlogConnection: %s", str(e))
            # We really have nowhere to log this, if the netlog connection
            # does not work, we can assume that any logging won't work either.
            # So we just fail silently.
            self.close()

    def close(self):
        try:
            self.sock.close()
        except Exception:
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
