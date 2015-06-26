#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import socket
from bson import BSON
from datetime import datetime
from subprocess import check_output
from filetimes import dt_to_filetime

class CuckooHost:

    sockets = {}
    descriptions = {}
    launch_times = {}

    def __init__(self, host_ip, host_port):
        self.ip = host_ip
        self.port = host_port

    def send_api(self, thing):
        """  """
        pid = thing.pid
        api = thing.api

        # We're required to report results of tracing a target process to
        # *its own* result server. So create a communication socket...
        if not self.sockets.has_key(pid):
            self.sockets[pid] = self._socket_for_pid(pid)
            if not self.sockets[pid]:
                raise Exception("CuckooHost error: could not create socket.")
            self._send_new_process(thing)
        # ... and don't forget to explain every single API call again
        self.descriptions.setdefault(pid, ["__process__", "__thread__"])
        try:
            lookup_idx = self.descriptions[pid].index(api)
        except ValueError:
            self.descriptions[pid].append(api)
            lookup_idx = len(self.descriptions[pid]) - 1
            self._send_api_description(lookup_idx, thing)

        # Here's an api object:
        # {
        #     "I"    : (int)<index in the API lookup table>,
        #     "T"    : (int)<caller thread id>,
        #     "t"    : (int)<time (in milliseconds) since a process launch>,
        #     "args" : [
        #         (int)<1 if this API call was successfull, 0 otherwise>,
        #         (int)<return value>,
        #         (any)<value the first argument>,
        #         (any)<value the second argument>,
        #                       ...
        #         (any)<value the n-th argument>,
        #     ]
        # }
        self.sockets[pid].sendall(BSON.encode({
            "I"    : lookup_idx,
            "T"    : thing.tid,
            "t"    : 1000*(thing.timestamp - self.launch_times[pid]),
            "args" : self._prepare_args(thing)
        }))

    def _socket_for_pid(self, pid):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        # Prepare the result server to accept data in BSON format
        s.sendall("BSON\n")
        return s

    def _send_api_description(self, lookup_idx, thing):
        # Here's an api description object:
        # {
        #     "I"        : (string)<index in the API lookup table>,
        #     "name"     : (string)<API name>,
        #     "type"     : "info",
        #     "category" : (string)<an API category (e.g. "memory" or "network")>
        #     "args"     : [
        #         "is_success",
        #         "retval",
        #         (string)<description of the first argument>,
        #         (string)<description of the second argument>,
        #                       ...
        #         (string)<description of the n-th argument>,
        #     ]
        # }
        self.sockets[thing.pid].sendall(BSON.encode({
            "I"        : lookup_idx,
            "name"     : thing.api,
            "type"     : "info",
            "category" : "unknown", # FIXME(rodionovd): put an actual value here
            "args"     : self._args_description(thing)
        }))

    def _prepare_args(self, thing):
        result = [
            1,  # FIXME(rodionovd): put an actual "is_success" value here
            thing.retval
        ]
        for arg in thing.args: result.append(arg)
        return result

    def _args_description(self, thing):
        """ """
        description = ["is_success", "retval"]
        for arg_idx in range(0, len(thing.args)):
            # TODO(rodionovd): we need actual names here
            description += ["arg%d" % arg_idx]
        return description

    def _send_new_process(self, thing):
        """  """
        pid = thing.pid
        # Remember when this process was born
        # FIXME(rodionovd): increase resulution of the timestamps
        # (from 1 second to like 1 millisecond)
        self.launch_times[pid] = thing.timestamp
        # Describe the __process__ notification
        self.sockets[pid].sendall(BSON.encode({
            "I"        : 0,
            "name"     : "__process__",
            "type"     : "info",
            "category" : "unknown",
            "args"     : [
                "is_success",
                "retval",
                "TimeLow", "TimeHigh",
                "ProcessIdentifier", "ParentProcessIdentifier",
                "ModulePath"
            ]
        }))
        # Convert our unix timestamp into Windows's FILETIME because Cuckoo
        # result server expect timestamps to be in this format
        filetime = self._filetime_from_timestamp(thing.timestamp)
        # Get process name (aka module path)
        module = self._proc_name_from_pid(pid)
        self.sockets[pid].sendall(BSON.encode({
            "I"    : 0,
            "T"    : thing.tid,
            "t"    : 0,
            "args" : [
                1,
                0,
                # TimeLow (first 32bits) and TimeHigh (last 32bits)
                (filetime) & 0xffffffff, (filetime) >> 32,
                thing.pid, thing.ppid,
                # ModulePath
                module
            ]
        }))

    def _filetime_from_timestamp(self, ts):
        # Timezones are hard, sorry
        dt = datetime.fromtimestamp(ts)
        delta_from_utc = dt - datetime.utcfromtimestamp(ts)
        return dt_to_filetime(dt, delta_from_utc)

    def _proc_name_from_pid(self, pid):
        # The first line of an output is reserved for `ps` headers and the
        # second one contains a process path
        try:
            ps_output = check_output(["/bin/ps", "-p", str(pid), "-o", "comm"])
            return ps_output.split("\n")[1]
        except:
            return "unknown"
