# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import struct
import datetime
import string

try: import bson
except: pass

from lib.cuckoo.common.apicategories import categories as APICATEGORIES
from lib.cuckoo.common.utils import get_filename_from_path, time_from_cuckoomon

log = logging.getLogger(__name__)

REG_NONE                = 0
REG_SZ                  = 1
REG_EXPAND_SZ           = 2
REG_BINARY              = 3
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD               = 4
REG_DWORD_BIG_ENDIAN    = 5


class BsonParser(object):
    def __init__(self, handler):
        self.handler = handler
        self.infomap = {}

    def read_next_message(self):
        data = self.handler.read(4)
        blen = struct.unpack("I", data)[0]

        data += self.handler.read(blen-4)

        try:
            dec = bson.BSON(data).decode()
        except Exception as e:
            log.warning("BsonParser decoding problem {0} on data {1}".format(e,repr(data)))
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
            argnames = dec.get("args", [])

            self.infomap[index] = (name, argnames)

        elif mtype == "debug":
            log.info("Debug message from monitor: {0}".format(dec.get("msg", "")))

        elif mtype == "new_process":
            # new_process message from VMI monitor
            vmtime = datetime.datetime.fromtimestamp(dec.get("starttime", 0))
            procname = dec.get("name", "NONAME")
            ppid = 0
            modulepath = "DUMMY"

            self.handler.log_process(context, vmtime, pid, ppid, modulepath, procname)

        else: # regular api call
            if not index in self.infomap:
                log.warning("Got API with unknown index - monitor needs to explain first: {0}".format(dec))
                return True

            apiname, argnames = self.infomap[index]
            args = dec.get("args", [])

            if len(args) != len(argnames):
                log.warning("Inconsistent arg count (compared to arg names) on {2}: {0} names {1}".format(dec, argnames, apiname))
                return True

            argdict = dict((argnames[i], args[i]) for i in range(len(args)))

            if apiname == "__process__":
                # special new process message from cuckoomon
                timelow = argdict["TimeLow"]
                timehigh = argdict["TimeHigh"]
                # FILETIME is 100-nanoseconds from 1601 :/
                vmtimeunix = (timelow + (timehigh << 32)) / 10000000.0 - 11644473600
                vmtime = datetime.datetime.fromtimestamp(vmtimeunix)

                pid = argdict["ProcessIdentifier"]
                ppid = argdict["ParentProcessIdentifier"]
                modulepath = argdict["ModulePath"]
                procname = get_filename_from_path(modulepath)

                self.handler.log_process(context, vmtime, pid, ppid, modulepath, procname)
                return True

            elif apiname == "__thread__":
                pid = argdict["ProcessIdentifier"]
                self.handler.log_thread(context, pid)
                return True

            context[1] = argdict.pop("is_success", 1)
            context[2] = argdict.pop("retval", 0)
            arguments = argdict.items()
            arguments += dec.get("aux", {}).items()

            modulename = "NONE"
            category = APICATEGORIES.get(apiname, "unknown")

            self.handler.log_call(context, apiname, category, arguments)

        return True
