# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import errno
import json
import os
import socket
import select
import logging
import datetime
import SocketServer
import threading

from lib.cuckoo.common.abstracts import ProtocolHandler
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.utils import create_folder, Singleton
from lib.cuckoo.core.log import task_log_start, task_log_stop

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
                SocketServer.ThreadingTCPServer.__init__(
                    self, server_addr, ResultHandler, *args, **kwargs
                )
            except Exception as e:
                if e.errno == errno.EADDRINUSE:
                    if self.cfg.resultserver.get("force_port"):
                        raise CuckooCriticalError(
                            "Cannot bind ResultServer on port %d, "
                            "bailing." % self.port
                        )
                    else:
                        log.warning("Cannot bind ResultServer on port %s, "
                                    "trying another port.", self.port)
                        self.port += 1
                elif e.errno == errno.EADDRNOTAVAIL:
                    raise CuckooCriticalError(
                        "Unable to bind ResultServer on %s:%s %s. This "
                        "usually happens when you start Cuckoo without "
                        "bringing up the virtual interface associated with "
                        "the ResultServer IP address. Please refer to "
                        "http://docs.cuckoosandbox.org/en/latest/faq/#troubles-problem"
                        " for more information." % (ip, self.port, e)
                    )
                else:
                    raise CuckooCriticalError(
                        "Unable to bind ResultServer on %s:%s: %s" %
                        (ip, self.port, e)
                    )
            else:
                log.debug("ResultServer running on %s:%s.", ip, self.port)
                self.servethread = threading.Thread(target=self.serve_forever)
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
        self.rawlogfd = None
        self.protocol = None
        self.startbuf = ""
        self.end_request = threading.Event()
        self.done_event = threading.Event()
        self.server.register_handler(self)

        if hasattr(select, "poll"):
            self.poll = select.poll()
            self.poll.register(self.request, select.POLLIN)
        else:
            self.poll = None

    def finish(self):
        self.done_event.set()

        if self.protocol:
            self.protocol.close()
        if self.rawlogfd:
            self.rawlogfd.close()

    def wait_sock_or_end(self):
        while True:
            if self.end_request.isSet():
                return False

            if self.poll:
                if self.poll.poll(1000):
                    return True
            else:
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

                if len(self.startbuf) > 0x10000:
                    raise CuckooResultError(
                        "Somebody is knowingly overflowing the startbuf "
                        "buffer, possibly to use excessive amounts of memory."
                    )

        return buf

    def read_any(self):
        if not self.wait_sock_or_end():
            raise Disconnect()
        tmp = self.request.recv(BUFSIZE)
        if not tmp:
            raise Disconnect()
        return tmp

    def read_newline(self, strip=False):
        buf = ""
        while "\n" not in buf:
            buf += self.read(1)

        if strip:
            buf = buf.strip()

        return buf

    def negotiate_protocol(self):
        protocol = self.read_newline(strip=True)

        # Command with version number.
        if " " in protocol:
            command, version = protocol.split()
            version = int(version)
        else:
            command, version = protocol, None

        if command == "BSON":
            self.protocol = BsonParser(self, version)
        elif command == "FILE":
            self.protocol = FileUpload(self, version)
        elif command == "LOG":
            self.protocol = LogHandler(self, version)
        else:
            raise CuckooOperationalError(
                "Netlog failure, unknown protocol requested."
            )

        self.protocol.init()

    def handle(self):
        ip, port = self.client_address
        self.connect_time = datetime.datetime.now()

        self.storagepath = self.server.build_storage_path(ip)
        if not self.storagepath:
            return

        task, _ = self.server.get_ctx_for_ip(ip)
        task_log_start(task.id)

        # Create all missing folders for this analysis.
        self.create_folders()

        try:
            # Initialize the protocol handler class for this connection.
            self.negotiate_protocol()

            for event in self.protocol:
                if isinstance(self.protocol, BsonParser) and event["type"] == "process":
                    self.open_process_log(event)

        except CuckooResultError as e:
            log.warning(
                "ResultServer connection stopping because of "
                "CuckooResultError: %s.", e
            )
        except (Disconnect, socket.error):
            pass
        except:
            log.exception("FIXME - exception in resultserver connection %s",
                          self.client_address)

        task_log_stop(task.id)

    def open_process_log(self, event):
        pid = event["pid"]
        ppid = event["ppid"]
        procname = event["process_name"]

        if self.rawlogfd:
            log.debug(
                "ResultServer got a new process message but already "
                "has pid %d ppid %s procname %s.", pid, ppid, procname
            )
            raise CuckooResultError(
                "ResultServer connection state inconsistent."
            )

        if not isinstance(pid, (int, long)):
            raise CuckooResultError(
                "An invalid process identifier has been provided, this "
                "could be a potential security hazard."
            )

        # Only report this process when we're tracking it.
        if event["track"]:
            log.debug(
                "New process (pid=%s, ppid=%s, name=%s)",
                pid, ppid, procname
            )

        filepath = os.path.join(self.storagepath, "logs", "%s.bson" % pid)
        self.rawlogfd = open(filepath, "wb")
        self.rawlogfd.write(self.startbuf)

    def create_folders(self):
        folders = "shots", "files", "logs", "buffer"

        for folder in folders:
            try:
                create_folder(self.storagepath, folder=folder)
            except CuckooOperationalError:
                log.error("Unable to create folder %s" % folder)
                return False

class FileUpload(ProtocolHandler):
    RESTRICTED_DIRECTORIES = "reports/",
    lock = threading.Lock()

    def init(self):
        self.upload_max_size = \
            self.handler.server.cfg.resultserver.upload_max_size
        self.storagepath = self.handler.storagepath
        self.fd = None

        self.filelog = os.path.join(self.handler.storagepath, "files.json")

    def __iter__(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin

        dump_path = self.handler.read_newline(strip=True).replace("\\", "/")

        if self.version >= 2:
            filepath = self.handler.read_newline(strip=True)
            pids = map(int, self.handler.read_newline(strip=True).split())
        else:
            filepath, pids = None, []

        log.debug("File upload request for %s", dump_path)

        dir_part, filename = os.path.split(dump_path)

        if "./" in dump_path or not dir_part or dump_path.startswith("/"):
            raise CuckooOperationalError(
                "FileUpload failure, banned path: %s" % dump_path
            )

        for restricted in self.RESTRICTED_DIRECTORIES:
            if restricted in dir_part:
                raise CuckooOperationalError(
                    "FileUpload failure, banned path."
                )

        try:
            create_folder(self.storagepath, dir_part)
        except CuckooOperationalError:
            log.error("Unable to create folder %s", dir_part)
            return

        file_path = os.path.join(self.storagepath, dump_path)

        if not file_path.startswith(self.storagepath):
            raise CuckooOperationalError(
                "FileUpload failure, path sanitization failed."
            )

        if os.path.exists(file_path):
            log.warning(
                "Analyzer tried to overwrite an existing file, "
                "closing connection."
            )
            return

        self.fd = open(file_path, "wb")
        chunk = self.handler.read_any()
        while chunk:
            self.fd.write(chunk)

            if self.fd.tell() >= self.upload_max_size:
                log.warning(
                    "Uploaded file length larger than upload_max_size, "
                    "stopping upload."
                )
                self.fd.write("... (truncated)")
                break

            try:
                chunk = self.handler.read_any()
            except:
                break

        self.lock.acquire()

        with open(self.filelog, "a+b") as f:
            f.write("%s\n" % json.dumps({
                "path": dump_path,
                "filepath": filepath,
                "pids": pids,
            }))

        self.lock.release()

        log.debug("Uploaded file length: %s", self.fd.tell())
        return
        yield

    def close(self):
        if self.fd:
            self.fd.close()

class LogHandler(ProtocolHandler):
    def init(self):
        self.logpath = os.path.join(self.handler.storagepath, "analysis.log")
        self.fd = self._open()
        log.debug("LogHandler for live analysis.log initialized.")

    def __iter__(self):
        if not self.fd:
            return

        while True:
            try:
                buf = self.handler.read_newline(strip=False)
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
