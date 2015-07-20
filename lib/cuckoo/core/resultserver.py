# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket
import select
import logging
import datetime
import SocketServer
from threading import Event, Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.utils import create_folder, Singleton

log = logging.getLogger(__name__)

BUFSIZE = 16 * 1024

class Disconnect(Exception):
    pass

class ResultServer(SocketServer.ThreadingTCPServer, object):
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

        ip = self.cfg.resultserver.ip
        self.port = int(self.cfg.resultserver.port)
        while True:
            try:
                server_addr = ip, self.port
                SocketServer.ThreadingTCPServer.__init__(self,
                                                         server_addr,
                                                         ResultHandler,
                                                         *args,
                                                         **kwargs)
            except Exception as e:
                # In Linux /usr/include/asm-generic/errno-base.h.
                # EADDRINUSE  98 (Address already in use)
                # In Mac OS X or FreeBSD:
                # EADDRINUSE 48 (Address already in use)
                if e.errno == 98 or e.errno == 48:
                    log.warning("Cannot bind ResultServer on port %s, "
                                "trying another port.", self.port)
                    self.port += 1
                else:
                    raise CuckooCriticalError("Unable to bind ResultServer on "
                                              "{0}:{1}: {2}".format(
                                                  ip, self.port, str(e)))
            else:
                log.debug("ResultServer running on %s:%s.", ip, self.port)
                self.servethread = Thread(target=self.serve_forever)
                self.servethread.setDaemon(True)
                self.servethread.start()
                break

    def add_task(self, task, machine):
        """Register a task/machine with the ResultServer."""
        self.analysistasks[machine.ip] = task, machine
        self.analysishandlers[task.id] = []

    def del_task(self, task, machine):
        """Delete ResultServer state and wait for pending RequestHandlers."""
        x = self.analysistasks.pop(machine.ip, None)
        if not x:
            log.warning("ResultServer did not have %s in its task info.",
                        machine.ip)
        handlers = self.analysishandlers.pop(task.id, None)
        for h in handlers:
            h.end_request.set()
            h.done_event.wait()

    def register_handler(self, handler):
        """Register a RequestHandler so that we can later wait for it."""
        task, machine = self.get_ctx_for_ip(handler.client_address[0])
        if not task or not machine:
            return False

        self.analysishandlers[task.id].append(handler)

    def get_ctx_for_ip(self, ip):
        """Return state for this IP's task."""
        x = self.analysistasks.get(ip)
        if not x:
            log.critical("ResultServer unable to map ip to context: %s.", ip)
            return None, None

        return x

    def build_storage_path(self, ip):
        """Initialize analysis storage folder."""
        task, machine = self.get_ctx_for_ip(ip)
        if not task or not machine:
            return

        return os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task.id))

class ResultHandler(SocketServer.BaseRequestHandler):
    """Result handler.

    This handler speaks our analysis log network protocol.
    """

    def setup(self):
        self.logfd = None
        self.rawlogfd = None
        self.protocol = None
        self.startbuf = ""
        self.end_request = Event()
        self.done_event = Event()
        self.pid, self.ppid, self.procname = None, None, None
        self.server.register_handler(self)

    def finish(self):
        self.done_event.set()

        if self.protocol:
            self.protocol.close()
        if self.logfd:
            self.logfd.close()
        if self.rawlogfd:
            self.rawlogfd.close()

    def wait_sock_or_end(self):
        while True:
            if self.end_request.isSet():
                return False
            rs, _, _ = select.select([self.request], [], [], 1)
            if rs:
                return True

    def seek(self, pos):
        pass

    def read(self, length):
        buf = ""
        while len(buf) < length:
            if not self.wait_sock_or_end():
                raise Disconnect()
            tmp = self.request.recv(length-len(buf))
            if not tmp:
                raise Disconnect()
            buf += tmp

        if isinstance(self.protocol, BsonParser):
            if self.rawlogfd:
                self.rawlogfd.write(buf)
            else:
                self.startbuf += buf
        return buf

    def read_any(self):
        if not self.wait_sock_or_end():
            raise Disconnect()
        tmp = self.request.recv(BUFSIZE)
        if not tmp:
            raise Disconnect()
        return tmp

    def read_newline(self):
        buf = ""
        while "\n" not in buf:
            buf += self.read(1)
        return buf

    def negotiate_protocol(self):
        # Read until newline.
        buf = self.read_newline()

        if "BSON" in buf:
            self.protocol = BsonParser(self)
        elif "FILE" in buf:
            self.protocol = FileUpload(self)
        elif "LOG" in buf:
            self.protocol = LogHandler(self)
        else:
            raise CuckooOperationalError("Netlog failure, unknown "
                                         "protocol requested.")

    def handle(self):
        ip, port = self.client_address
        self.connect_time = datetime.datetime.now()

        self.storagepath = self.server.build_storage_path(ip)
        if not self.storagepath:
            return

        # Create all missing folders for this analysis.
        self.create_folders()

        try:
            # Initialize the protocol handler class for this connection.
            self.negotiate_protocol()

            for event in self.protocol:
                if isinstance(self.protocol, BsonParser) and event["type"] == "process":
                    self.open_process_log(event)

        except CuckooResultError as e:
            log.warning("ResultServer connection stopping because of "
                        "CuckooResultError: %s.", str(e))
        except (Disconnect, socket.error):
            pass
        except:
            log.exception("FIXME - exception in resultserver connection %s",
                          str(self.client_address))

        log.debug("Connection closed: {0}:{1}".format(ip, port))

    def open_process_log(self, event):
        pid = event["pid"]
        ppid = event["ppid"]
        procname = event["process_name"]

        if self.pid is not None:
            log.debug("ResultServer got a new process message but already "
                      "has pid %d ppid %s procname %s.",
                      pid, str(ppid), procname)
            raise CuckooResultError("ResultServer connection state "
                                    "inconsistent.")

        log.debug("New process (pid=%s, ppid=%s, name=%s)",
                  pid, ppid, procname)
        path = os.path.join(self.storagepath, "logs", str(pid) + ".bson")
        self.rawlogfd = open(path, "wb")
        self.rawlogfd.write(self.startbuf)

        self.pid, self.ppid, self.procname = pid, ppid, procname

    def create_folders(self):
        folders = "shots", "files", "logs"

        for folder in folders:
            try:
                create_folder(self.storagepath, folder=folder)
            except CuckooOperationalError:
                log.error("Unable to create folder %s" % folder)
                return False


class FileUpload(object):
    RESTRICTED_DIRECTORIES = "reports/",

    def __init__(self, handler):
        self.handler = handler
        self.upload_max_size = \
            self.handler.server.cfg.resultserver.upload_max_size
        self.storagepath = self.handler.storagepath
        self.fd = None

    def __iter__(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin

        buf = self.handler.read_newline().strip().replace("\\", "/")
        log.debug("File upload request for %s", buf)

        dir_part, filename = os.path.split(buf)

        if "./" in buf or not dir_part or buf.startswith("/"):
            raise CuckooOperationalError("FileUpload failure, banned path.")

        for restricted in self.RESTRICTED_DIRECTORIES:
            if restricted in dir_part:
                raise CuckooOperationalError("FileUpload failure, banned path.")

        try:
            create_folder(self.storagepath, dir_part)
        except CuckooOperationalError:
            log.error("Unable to create folder %s", dir_part)
            return

        file_path = os.path.join(self.storagepath, buf.strip())

        if not file_path.startswith(self.storagepath):
            raise CuckooOperationalError("FileUpload failure, path sanitization failed.")

        if os.path.exists(file_path):
            log.warning("Analyzer tried to overwrite an existing file, closing connection.")
            return

        self.fd = open(file_path, "wb")
        chunk = self.handler.read_any()
        while chunk:
            self.fd.write(chunk)

            if self.fd.tell() >= self.upload_max_size:
                log.warning("Uploaded file length larger than upload_max_size, stopping upload.")
                self.fd.write("... (truncated)")
                break

            try:
                chunk = self.handler.read_any()
            except:
                break

        log.debug("Uploaded file length: %s", self.fd.tell())
        return
        yield

    def close(self):
        if self.fd:
            self.fd.close()

class LogHandler(object):
    def __init__(self, handler):
        self.handler = handler
        self.logpath = os.path.join(handler.storagepath, "analysis.log")
        self.fd = self._open()
        log.debug("LogHandler for live analysis.log initialized.")

    def __iter__(self):
        if not self.fd:
            return

        while True:
            try:
                buf = self.handler.read_newline()
            except Disconnect:
                break

            if not buf:
                break

            self.fd.write(buf)
            self.fd.flush()

        return
        yield

    def close(self):
        if self.fd:
            self.fd.close()

    def _open(self):
        if not os.path.exists(self.logpath):
            return open(self.logpath, "wb")

        log.debug("Log analysis.log already existing, appending data.")
        fd = open(self.logpath, "ab")

        # add a fake log entry, saying this had to be re-opened
        #  use the same format as the default logger, in case anyone wants to parse this
        #  2015-02-23 12:05:05,092 [lib.api.process] DEBUG: Using QueueUserAPC injection.
        now = datetime.datetime.now()
        print >>fd, "\n%s,%03.0f [lib.core.resultserver] WARNING: This log file was re-opened, log entries will be appended." % (
            now.strftime("%Y-%m-%d %H:%M:%S"), now.microsecond / 1000.0
        )

        return fd
