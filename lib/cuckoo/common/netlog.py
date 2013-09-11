# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import struct
import datetime
import string

from lib.cuckoo.common.logtbl import table as LOGTBL
from lib.cuckoo.common.utils import get_filename_from_path, time_from_cuckoomon

log = logging.getLogger(__name__)

REG_NONE                = 0
REG_SZ                  = 1
REG_EXPAND_SZ           = 2
REG_BINARY              = 3
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD               = 4
REG_DWORD_BIG_ENDIAN    = 5

# should probably prettify this
def expand_format(fs):
    out = ""
    i = 0
    while i<len(fs):
        x = fs[i]
        if x in string.digits:
            out += fs[i+1] * int(x)
            i += 1
        else:
            out += x
        i += 1
    return out

class NetlogParser(object):
    def __init__(self, handler):
        self.handler = handler

        self.formatmap = {
            "s": self.read_string,
            "S": self.read_string,
            "u": self.read_string,
            "U": self.read_string,
            "b": self.read_buffer,
            "B": self.read_buffer,
            "i": self.read_int32,
            "l": self.read_int32,
            "L": self.read_int32,
            "p": self.read_ptr,
            "P": self.read_ptr,
            "o": self.read_string,
            "O": self.read_string,
            "a": self.read_argv,
            "A": self.read_argv,
            "r": self.read_registry,
            "R": self.read_registry,
        }

    def read_next_message(self):
        apiindex, status = struct.unpack("BB", self.handler.read(2))
        returnval, tid, timediff = struct.unpack("III", self.handler.read(12))
        context = (apiindex, status, returnval, tid, timediff)

        if apiindex == 0:
            # new process message
            timelow = self.read_int32()
            timehigh = self.read_int32()
            # FILETIME is 100-nanoseconds from 1601 :/
            vmtimeunix = (timelow + (timehigh << 32)) / 10000000.0 - 11644473600
            vmtime = datetime.datetime.fromtimestamp(vmtimeunix)

            pid = self.read_int32()
            ppid = self.read_int32()
            modulepath = self.read_string()
            procname = get_filename_from_path(modulepath)
            self.handler.log_process(context, vmtime, pid, ppid, modulepath, procname)

        elif apiindex == 1:
            # new thread message
            pid = self.read_int32()
            self.handler.log_thread(context, pid)

        else:
            # actual API call
            try:
                apiname, modulename, parseinfo = LOGTBL[apiindex]
            except IndexError:
                log.debug("Netlog LOGTBL lookup error for API index {0} (pid={1}, tid={2})".format(apiindex, self.pid, tid))
                return False

            formatspecifiers, argnames = expand_format(parseinfo[0]), parseinfo[1:]
            arguments = []
            for pos in range(len(formatspecifiers)):
                fs = formatspecifiers[pos]
                argname = argnames[pos]
                fn = self.formatmap.get(fs, None)
                if fn:
                    r = fn()
                    arguments.append((argname, r))
                else:
                    log.warning("No handler for format specifier {0} on apitype {1}".format(fs,apiname))

            self.handler.log_call(context, apiname, modulename, arguments)

        return True

    def read_int32(self):
        """Reads a 32bit integer from the socket."""
        return struct.unpack("I", self.handler.read(4))[0]

    def read_ptr(self):
        """Read a pointer from the socket."""
        value = self.read_int32()
        return "0x%08x" % value

    def read_string(self):
        """Reads an utf8 string from the socket."""
        length, maxlength = struct.unpack("II", self.handler.read(8))
        s = self.handler.read(length)
        if maxlength > length: s += "... (truncated)"
        return s

    def read_buffer(self):
        """Reads a memory socket from the socket."""
        length, maxlength = struct.unpack("II", self.handler.read(8))
        # only return the maxlength, as we don't log the actual buffer right now
        buf = self.handler.read(length)
        if maxlength > length: buf += " ... (truncated)"
        return buf

    def read_registry(self):
        """Read logged registry data from the socket."""
        typ = struct.unpack("I", self.handler.read(4))[0]
        # do something depending on type
        if typ == REG_DWORD_BIG_ENDIAN or typ == REG_DWORD_LITTLE_ENDIAN:
            value = self.read_int32()
        elif typ == REG_SZ or typ == REG_EXPAND_SZ:
            value = self.read_string()
        else:
            value = "(unable to dump buffer content)"
        return value

    def read_list(self, fn):
        """Reads a list of _fn_ from the socket."""
        count = struct.unpack("I", self.handler.read(4))[0]
        ret = []
        for x in xrange(count):
            item = fn()
            ret.append(item)
        return ret

    def read_argv(self):
        return self.read_list(self.read_string)