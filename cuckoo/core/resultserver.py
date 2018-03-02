# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# TODO:
# * NTFS ADS / windows fn protection
# * gevent doesn't bind until serve_forever()
# * replace threading with gevent locks (needed?)
# * lock all filesystem operations?
# * lock in ProtocolHandler for .running?
# * fd leaking / no timeout
# * consider creating a folder whitelist
from __future__ import print_function

import errno
import datetime
import gevent.server
import gevent.pool
import json
import logging
import os
import struct
import threading

from cuckoo.common.abstracts import ProtocolHandler
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooResultError
from cuckoo.common.files import Folders
from cuckoo.common.utils import Singleton
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

# Maximum line length to read for netlog messages, to avoid memory exhaustion
MAX_NETLOG_LINE = 4 * 1024

BUFSIZE = 16 * 1024

NETLOG_RECV_TIMEOUT = 60


class HandlerContext:
    """Holds context for protocol handlers"""
    def __init__(self, storagepath, sock):
        # The part where artifacts will be stored
        self.storagepath = storagepath
        self.sock = sock.makefile(mode='rb')

    def __del__(self):
        self.sock.close()

    def read(self, size):
        buf = self.sock.read(size)
        if not buf:
            raise EOFError
        return buf

    def read_newline(self):
        line = self.sock.readline(MAX_NETLOG_LINE)
        if not line:
            raise EOFError
        elif not line.endswith('\n'):
            raise CuckooOperationalError('Received overly long line')
        return line[:-1]

    def read_any(self):
        buf = self.sock.read(BUFSIZE)
        if not buf:
            raise EOFError
        return buf


class FileUpload(ProtocolHandler):
    RESTRICTED_DIRECTORIES = "reports/",

    def init(self):
        self.upload_max_size = config("cuckoo:resultserver:upload_max_size")
        self.storagepath = self.handler.storagepath
        self.fd = None
        self.filelog = os.path.join(self.handler.storagepath, "files.json")

    def handle(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin

        dump_path = self.handler.read_newline().replace("\\", "/")

        if self.version >= 2:
            filepath = self.handler.read_newline()
            pids = map(int, self.handler.read_newline().split())
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
            Folders.create(self.storagepath, dir_part)
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

        with open(self.filelog, "a+b") as f:
            f.write("%s\n" % json.dumps({
                "path": dump_path,
                "filepath": filepath,
                "pids": pids,
            }))

        log.debug("Uploaded file length: %s", self.fd.tell())
        self.fd.close()

    def close(self):
        if self.fd:
            self.fd.close()

class LogHandler(ProtocolHandler):
    # TODO: not protected against opening multiple times
    def init(self):
        self.logpath = os.path.join(self.handler.storagepath, "analysis.log")
        self.fd = self._open()
        log.debug("LogHandler for live analysis.log initialized.")

    def handle(self):
        if not self.fd:
            return

        while True:
            try:
                buf = self.handler.read_any()
            except EOFError:
                break

            if not buf:
                break

            self.fd.write(buf)
            self.fd.flush()  # Expensive...

    def close(self):
        if self.fd:
            self.fd.close()

    def _open(self):
        if not os.path.exists(self.logpath):
            # (Race condition)
            return open(self.logpath, "wb")

        log.debug("Log analysis.log already existing, appending data.")
        fd = open(self.logpath, "ab")

        # add a fake log entry, saying this had to be re-opened
        #  use the same format as the default logger, in case anyone wants to parse this
        #  2015-02-23 12:05:05,092 [lib.api.process] DEBUG: Using QueueUserAPC injection.
        now = datetime.datetime.now()
        print("\n", now.strftime("%Y-%m-%d %H:%M:%S",),
              now.microsecond / 1000.0,
              " [lib.core.resultserver] WARNING: This log file was re-opened, log entries will be appended.",
              sep='', file=fd)
        return fd

class BsonStore(ProtocolHandler):
    def init(self):
        # We cheat a little bit through the "version" variable, but that's
        # acceptable and backwards compatible (for now). Backwards compatible
        # in the sense that newer Cuckoo Monitor binaries work with older
        # versions of Cuckoo, the other way around doesn't apply here.
        self.f = open(os.path.join(self.handler.storagepath,
                                   "logs", "%d.bson" % self.version), "wb")

    def handle(self):
        while self.running:
            # TODO: just loop read_any
            try:
                lenbuf = self.handler.read(4)
                if len(lenbuf) != 4:
                    log.warning("BsonStore short read")
                    break
            except EOFError:
                break

            length = struct.unpack("I", lenbuf)[0]
            buf = self.handler.read(length)
            if len(buf) != length:
                log.warning("BsonStore short read")
                break

            # TODO Handle out of disk space.
            self.f.write(lenbuf + buf)

    def close(self):
        self.f.close()


class GeventResultServerWorker(gevent.server.StreamServer):
    """The new ResultServer, providing a huge performance boost as well as
    implementing a new dropped file storage format avoiding small fd limits.

    The old ResultServer would start a new thread per socket, greatly impacting
    the overall performance of Cuckoo Sandbox. The new ResultServer uses
    so-called Greenlets, low overhead green-threads by Gevent, imposing much
    less kernel overhead.

    Furthermore, instead of writing each dropped file to its own location (in
    $CWD/storage/analyses/<task_id>/files/<partial_hash>_filename.ext) it's
    capable of storing all dropped files in a streamable container format. This
    is one of various steps to start being able to use less fd's in Cuckoo.
    """
    commands = {
        "BSON": BsonStore,
        "FILE": FileUpload,
        "LOG": LogHandler,
    }
    handler_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        super(GeventResultServerWorker, self).__init__(*args, **kwargs)

        # Store IP address to task_id mapping
        self.tasks = {}

        # Store running handlers for task_id
        self.handlers = {}

    def do_run(self):
        self.serve_forever()

    def add_task(self, task_id, ipaddr):
        self.tasks[ipaddr] = task_id

    def del_task(self, task_id, ipaddr):
        """Delete ResultServer state and wait for pending RequestHandlers."""
        if self.tasks.pop(ipaddr, None) is None:
            log.warning("ResultServer did not have a task with ID %s",
                        task_id)

        with self.handler_lock:
            socks = self.handlers.pop(task_id, set())
            for sock in socks:
                sock.close()

    def handle(self, sock, addr):
        ipaddr = addr[0]
        task_id = self.tasks.get(ipaddr)
        if not task_id:
            log.warning("ResultServer did not have a task for IP %s", ipaddr)
            return

        storagepath = cwd(analysis=task_id)
        ctx = HandlerContext(storagepath, sock)
        task_log_start(task_id)
        try:
            protocol = self.negotiate_protocol(ctx)

            # Registering the protocol allows for the handler getting its "running"
            # field set to False (among other use-cases in the future).
            with self.handler_lock:
                s = self.handlers.setdefault(task_id, set())
                s.add(sock)

            try:
                protocol.task_id = task_id  # TODO
                protocol.init()
                protocol.handle()
            finally:
                protocol.close()
                with self.handler_lock:
                    s.discard(sock)

        finally:
            sock.close()
            task_log_stop(task_id)

    def negotiate_protocol(self, ctx):
        header = ctx.read_newline()
        if " " in header:
            command, version = header.split()
            version = int(version)
        else:
            command, version = header, None
        if command not in self.commands:
            log.warning(
                "Unknown netlog protocol requested (%r), "
                "terminating connection.", command
            )
            return
        return self.commands[command](ctx, version)


class ResultServer(object):
    """Manager for the ResultServer worker and task state."""
    __metaclass__ = Singleton

    def __init__(self):
        self.thread = threading.Thread(target=self.create_bg_server)
        self.thread.daemon = True
        self.thread.start()

    def add_task(self, task, machine):
        """Register a task/machine with the ResultServer."""
        self.instance.add_task(task.id, machine.ip)

    def del_task(self, task, machine):
        """Delete running task and cancel existing handlers."""
        self.instance.del_task(task.id, machine.ip)

    def create_bg_server(self):
        ip = config("cuckoo:resultserver:ip")
        port = self.port = config("cuckoo:resultserver:port")
        pool_size = config('cuckoo:resultserver:poolsize')
        if pool_size:
            pool_size = int(pool_size)
        else:
            pool_size = 32

        pool = gevent.pool.Pool(pool_size)
        try:
            # TODO: support binding to port 0 for random port
            self.instance = GeventResultServerWorker((ip, port),
                                                     spawn=pool)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                    raise CuckooCriticalError(
                        "Cannot bind ResultServer on port %d "
                        "because it was in use, bailing." % port
                        )
            elif e.errno == errno.EADDRNOTAVAIL:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s %s. This "
                    "usually happens when you start Cuckoo without "
                    "bringing up the virtual interface associated with "
                    "the ResultServer IP address. Please refer to "
                    "https://cuckoo.sh/docs/faq/#troubles-problem "
                    "for more information." % (ip, port, e)
                )
            else:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s: %s" %
                    (ip, port, e)
                )
        self.instance.do_run()
