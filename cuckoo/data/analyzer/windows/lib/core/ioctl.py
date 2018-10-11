# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import socket
import struct

from lib.common.defines import (
    KERNEL32, GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING
)
from lib.common.rand import random_string

log = logging.getLogger(__name__)

# Random name for the zer0m0n driver.
driver_name = random_string(16)

CTL_CODE_BASE = 0x222000

class Ioctl(object):
    def __init__(self, pipepath):
        self.pipepath = pipepath

    def invoke(self, ctlcode, value, outlength=0x1000):
        device_handle = KERNEL32.CreateFileA(
            "\\\\.\\%s" % self.pipepath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
        ) % 2**32

        if device_handle == 0xffffffff:
            # Only report an error if the error is not "name not found",
            # indicating that no kernel analysis is currently taking place.
            if KERNEL32.GetLastError() != 2:
                log.warning(
                    "Error opening handle to driver (%s): %d!",
                    driver_name, KERNEL32.GetLastError()
                )
            return False

        out = ctypes.create_string_buffer(outlength)
        length = ctypes.c_uint()

        ret = KERNEL32.DeviceIoControl(
            device_handle, ctlcode, value, len(value), out,
            ctypes.sizeof(out), ctypes.byref(length), None
        )
        KERNEL32.CloseHandle(device_handle)

        if not ret:
            log.warning(
                "Error performing ioctl (0x%08x): %d!",
                ctlcode, KERNEL32.GetLastError()
            )
            return False

        return out.raw[:length.value]

class Zer0m0nIoctl(Ioctl):
    actions = [
        "addpid",
        "cmdpipe",
        "channel",
        "dumpmem",
        "yarald",
        "getpids",
        "hidepid",
        "dumpint",
        "resultserver",
    ]

    def invoke(self, action, buf):
        if action not in self.actions:
            raise RuntimeError("Invalid ioctl action: %s" % action)

        return Ioctl.invoke(
            self, CTL_CODE_BASE + self.actions.index(action) * 4, buf,
        )

    def addpid(self, pid):
        return self.invoke("addpid", struct.pack("Q", pid))

    def cmdpipe(self, pipe):
        return self.invoke("cmdpipe", "\x00".join(pipe + "\x00"))

    def channel(self, pipe):
        return self.invoke("channel", "\x00".join(pipe + "\x00"))

    def dumpmem(self, pid):
        return self.invoke("dumpmem", struct.pack("Q", pid))

    def yarald(self, rulepath):
        return self.invoke("yarald", open(rulepath, "rb").read())

    def getpids(self):
        pids = self.invoke("getpids", "pids") or ""
        return struct.unpack("Q"*(len(pids)/8), pids)

    def hidepid(self, pid):
        return self.invoke("hidepid", struct.pack("Q", pid))

    def dumpint(self, ms):
        return self.invoke("dumpint", struct.pack("I", ms))

    def resultserver(self, ip, port):
        # Just a regular SOCKADDR structure, up to 128 bytes
        if ":" in ip:
            rs = struct.pack("<H", socket.AF_INET6)
            rs += struct.pack("!H", port)
            rs += socket.inet_pton(socket.AF_INET6, ip)
        else:
            rs = struct.pack("<H", socket.AF_INET)
            rs += struct.pack("!H", port)
            rs += socket.inet_aton(ip)
        return self.invoke("resultserver", rs)

zer0m0n = Zer0m0nIoctl(driver_name)
