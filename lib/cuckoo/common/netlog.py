# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import struct
import datetime
import string

try:
    import bson
    HAVE_BSON = True
except ImportError:
    HAVE_BSON = False

if HAVE_BSON:
    # The BSON module provided by pymongo works through its "BSON" class.
    if hasattr(bson, "BSON"):
        bson_decode = lambda d: bson.BSON(d).decode()
    # The BSON module provided by "pip install bson" works through the
    # "loads" function (just like pickle etc.)
    elif hasattr(bson, "loads"):
        bson_decode = lambda d: bson.loads(d)
    else:
        HAVE_BSON = False

from lib.cuckoo.common.defines import REG_SZ, REG_EXPAND_SZ
from lib.cuckoo.common.defines import REG_DWORD_BIG_ENDIAN
from lib.cuckoo.common.defines import REG_DWORD_LITTLE_ENDIAN
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.logtbl import table as LOGTBL
from lib.cuckoo.common.utils import get_filename_from_path

log = logging.getLogger(__name__)


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


###############################################################################
# Custom Cuckoomon "Netlog" protocol - by skier and rep
# Kind of deprecated, more generic BSON protocol below
###############################################################################

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
            vmtimeunix = (timelow + (timehigh << 32))
            vmtimeunix = vmtimeunix / 10000000.0 - 11644473600
            try:
                vmtime = datetime.datetime.fromtimestamp(vmtimeunix)
            except:
                log.critical("vmtime in new-process-messsage out of range "
                             "(protocol out of sync?)")
                return False

            pid = self.read_int32()
            ppid = self.read_int32()

            try:
                modulepath = self.read_string()
                procname = get_filename_from_path(modulepath)
            except:
                log.exception("Exception in netlog protocol, stopping parser.")
                return False

            if len(procname) > 255:
                log.critical("Huge process name (>255), assuming netlog "
                             "protocol out of sync.")
                log.debug("Process name: %s", repr(procname))
                return False

            self.handler.log_process(context, vmtime, pid, ppid,
                                     modulepath, procname)

        elif apiindex == 1:
            # new thread message
            pid = self.read_int32()
            self.handler.log_thread(context, pid)

        else:
            # actual API call
            try:
                apiname, modulename, parseinfo = LOGTBL[apiindex]
            except IndexError:
                log.debug("Netlog LOGTBL lookup error for API index {0} "
                          "(pid={1}, tid={2})".format(apiindex, None, tid))
                return False

            formatspecifiers = expand_format(parseinfo[0])
            argnames = parseinfo[1:]
            arguments = []
            for pos in range(len(formatspecifiers)):
                fs = formatspecifiers[pos]
                argname = argnames[pos]
                fn = self.formatmap.get(fs, None)
                if fn:
                    try:
                        r = fn()
                    except:
                        log.exception("Exception in netlog protocol, "
                                      "stopping parser.")
                        return False

                    arguments.append((argname, r))
                else:
                    log.warning("No handler for format specifier {0} on "
                                "apitype {1}".format(fs, apiname))

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
        if length < 0 or length > 0x10000:
            log.critical("read_string length weirdness "
                         "length: %d maxlength: %d", length, maxlength)
            raise CuckooResultError("read_string length failure, "
                                    "protocol broken?")

        s = self.handler.read(length)
        if maxlength > length:
            s += "... (truncated)"
        return s

    def read_buffer(self):
        """Reads a memory socket from the socket."""
        length, maxlength = struct.unpack("II", self.handler.read(8))
        # only return the maxlength, as we don't log the actual
        # buffer right now
        buf = self.handler.read(length)
        if maxlength > length:
            buf += " ... (truncated)"
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


###############################################################################
# Generic BSON based protocol - by rep
# Allows all kinds of languages / sources to generate input for Cuckoo,
# thus we can reuse report generation / signatures for other API trace sources
###############################################################################

TYPECONVERTERS = {
    "p": lambda v: "0x%08x" % default_converter(v),
}

# 1 Mb max message length
MAX_MESSAGE_LENGTH = 20 * 1024 * 1024

def default_converter(v):
    # fix signed ints (bson is kind of limited there)
    if type(v) in (int, long) and v < 0:
        return v + 0x100000000
    return v

def check_names_for_typeinfo(arginfo):
    argnames = [i[0] if type(i) in (list, tuple) else i for i in arginfo]

    converters = []
    for i in arginfo:
        if type(i) in (list, tuple):
            r = TYPECONVERTERS.get(i[1], None)
            if not r:
                log.debug("Analyzer sent unknown format "
                          "specifier '{0}'".format(i[1]))
                r = default_converter
            converters.append(r)
        else:
            converters.append(default_converter)

    return argnames, converters


class BsonParser(object):
    def __init__(self, handler):
        self.handler = handler
        self.infomap = {}

        if not HAVE_BSON:
            log.critical("Starting BsonParser, but bson is not available! (install with `pip install bson`)")

    def read_next_message(self):
        data = self.handler.read(4)
        blen = struct.unpack("I", data)[0]
        if blen > MAX_MESSAGE_LENGTH:
            log.critical("BSON message larger than MAX_MESSAGE_LENGTH, "
                         "stopping handler.")
            return False

        data += self.handler.read(blen-4)

        try:
            dec = bson_decode(data)
        except Exception as e:
            log.warning("BsonParser decoding problem {0} on "
                        "data[:50] {1}".format(e, repr(data[:50])))
            return False

        mtype = dec.get("type", "none")
        index = dec.get("I", -1)
        tid = dec.get("T", 0)
        time = dec.get("t", 0)

        #context = (apiindex, status, returnval, tid, timediff)
        context = [index, 1, 0, tid, time]

        if mtype == "info":
            # API call index info message, explaining the argument names, etc
            name = dec.get("name", "NONAME")
            arginfo = dec.get("args", [])
            category = dec.get("category")

            # Bson dumps that were generated before cuckoomon exported the
            # "category" field have to get the category using the old method.
            if not category:
                # Try to find the entry/entries with this api name.
                category = [_ for _ in LOGTBL if _[0] == name]

                # If we found an entry, take its category, otherwise we take
                # the default string "unknown."
                category = category[0][1] if category else "unknown"

            argnames, converters = check_names_for_typeinfo(arginfo)
            self.infomap[index] = name, arginfo, argnames, converters, category

        elif mtype == "debug":
            log.info("Debug message from monitor: "
                     "{0}".format(dec.get("msg", "")))

        elif mtype == "new_process":
            # new_process message from VMI monitor
            vmtime = datetime.datetime.fromtimestamp(dec.get("starttime", 0))
            procname = dec.get("name", "NONAME")
            ppid = 0
            modulepath = "DUMMY"

            self.handler.log_process(context, vmtime, None, ppid,
                                     modulepath, procname)

        else:
            # regular api call
            if not index in self.infomap:
                log.warning("Got API with unknown index - monitor needs "
                            "to explain first: {0}".format(dec))
                return True

            apiname, arginfo, argnames, converters, category = self.infomap[index]
            args = dec.get("args", [])

            if len(args) != len(argnames):
                log.warning("Inconsistent arg count (compared to arg names) "
                            "on {2}: {0} names {1}".format(dec, argnames,
                                                           apiname))
                return True

            argdict = dict((argnames[i], converters[i](args[i]))
                           for i in range(len(args)))

            if apiname == "__process__":
                # special new process message from cuckoomon
                timelow = argdict["TimeLow"]
                timehigh = argdict["TimeHigh"]
                # FILETIME is 100-nanoseconds from 1601 :/
                vmtimeunix = (timelow + (timehigh << 32))
                vmtimeunix = vmtimeunix / 10000000.0 - 11644473600
                vmtime = datetime.datetime.fromtimestamp(vmtimeunix)

                pid = argdict["ProcessIdentifier"]
                ppid = argdict["ParentProcessIdentifier"]
                modulepath = argdict["ModulePath"]
                procname = get_filename_from_path(modulepath)

                self.handler.log_process(context, vmtime, pid, ppid,
                                         modulepath, procname)
                return True

            elif apiname == "__thread__":
                pid = argdict["ProcessIdentifier"]
                self.handler.log_thread(context, pid)
                return True

            context[1] = argdict.pop("is_success", 1)
            context[2] = argdict.pop("retval", 0)
            arguments = argdict.items()
            arguments += dec.get("aux", {}).items()

            self.handler.log_call(context, apiname, category, arguments)

        return True
