# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import socket
import threading

from ctypes import create_string_buffer, c_uint, byref, sizeof

from lib.common.defines import KERNEL32, PIPE_ACCESS_INBOUND, ERROR_MORE_DATA
from lib.common.defines import PIPE_TYPE_BYTE, PIPE_WAIT, ERROR_PIPE_CONNECTED
from lib.common.defines import PIPE_UNLIMITED_INSTANCES, INVALID_HANDLE_VALUE
from lib.common.defines import FILE_FLAG_WRITE_THROUGH, PIPE_READMODE_BYTE
from lib.common.defines import ERROR_BROKEN_PIPE

log = logging.getLogger(__name__)

sockets = {}
active = {}

class LogPipeHandler(threading.Thread):
    """The Log Pipe Handler forwards all data received from a local pipe to
    the Cuckoo server through a socket."""
    BUFSIZE = 0x10000

    def __init__(self, destination, pipe_handle):
        threading.Thread.__init__(self)
        self.destination = destination
        self.pipe_handle = pipe_handle

    def run(self):
        buf = create_string_buffer(self.BUFSIZE)
        bytes_read = c_uint()
        pid = c_uint()

        # The first four bytes indicate the process identifier. In case the
        # pipe handle is closed in an unknown way, reopening one and
        # specifying the same process identifier will reuse the same socket,
        # thus making it look like as if it was never closed in the first
        # place.
        success = KERNEL32.ReadFile(self.pipe_handle,
                                    byref(pid), sizeof(pid),
                                    byref(bytes_read), None)

        if not success or bytes_read.value != sizeof(pid):
            log.warning("Unable to read the process identifier of this "
                        "log pipe instance.")
            KERNEL32.CloseHandle(self.pipe_handle)
            return

        if active.get(pid.value):
            log.warning("A second log pipe handler for an active process is "
                        "being requested, denying request.")
            KERNEL32.CloseHandle(self.pipe_handle)
            return

        if pid.value not in sockets:
            sockets[pid.value] = socket.create_connection(self.destination)

        sock = sockets[pid.value]
        active[pid.value] = True

        while True:
            success = KERNEL32.ReadFile(self.pipe_handle,
                                        byref(buf), sizeof(buf),
                                        byref(bytes_read), None)

            if success or KERNEL32.GetLastError() == ERROR_MORE_DATA:
                sock.sendall(buf.raw[:bytes_read.value])
            # If we get the broken pipe error then this pipe connection has
            # been terminated for one reason or another. So break from the
            # loop and make the socket "inactive", that is, another pipe
            # connection can in theory pick it up. (This will only happen in
            # cases where malware for some reason broke our pipe connection).
            elif KERNEL32.GetLastError() == ERROR_BROKEN_PIPE:
                break
            else:
                log.warning("The log pipe handler has failed, last error %d.",
                            KERNEL32.GetLastError())
                break

        active[pid.value] = False

class LogPipeServer(threading.Thread):
    """The Log Pipe Server accepts incoming log pipe handlers and initializes
    them in a new thread."""
    def __init__(self, destination, pipe_name):
        threading.Thread.__init__(self)
        self.destination = destination
        self.pipe_name = pipe_name
        self.do_run = True

    def run(self):
        while self.do_run:
            pipe_handle = KERNEL32.CreateNamedPipeA(
                self.pipe_name, PIPE_ACCESS_INBOUND | FILE_FLAG_WRITE_THROUGH,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES, 0, self.BUFSIZE, 0, None)

            if pipe_handle == INVALID_HANDLE_VALUE:
                log.warning("Error opening logging pipe server.")
                continue

            if KERNEL32.ConnectNamedPipe(pipe_handle, None) or \
                    KERNEL32.GetLastError() == ERROR_PIPE_CONNECTED:
                handler = LogPipeHandler(self.destination, pipe_handle)
                handler.daemon = True
                handler.start()
            else:
                KERNEL32.CloseHandle(pipe_handle)
