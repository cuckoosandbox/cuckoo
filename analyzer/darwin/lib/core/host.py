#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import json
import socket
from os import path
from bson import BSON
from datetime import datetime
from subprocess import check_output, CalledProcessError
from filetimes import dt_to_filetime


class CuckooHost:
    """ Sending analysis results back to the Cuckoo Host.

    Currently it only supports sending results about API calls via send_api() -- see `apicalls` module.
    """
    sockets = {}
    descriptions = {}
    launch_times = {}
    human_readable_explanations = {}

    def __init__(self, host_ip, host_port):
        self.ip = host_ip
        self.port = host_port
        self._load_human_readable_explanations()

    def send_api(self, thing):
        """ Sends a new API notification to the Cuckoo host """
        pid = thing.pid
        api = thing.api

        # We're required to report results of tracing a target process to
        # *its own* result server. So create a communication socket...
        if pid not in self.sockets:
            self.sockets[pid] = self._create_socket()
            if not self.sockets[pid]:
                raise Exception("CuckooHost error: could not create socket.")
            # ... and don't forget to explain every single API call again
            self.descriptions.setdefault(pid, ["__process__", "__thread__"])
            self._send_new_process(thing)
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
        ms_since_process_launch = int(1000*thing.timestamp - 1000*self.launch_times[pid])
        self.sockets[pid].sendall(BSON.encode({
            "I"    : lookup_idx,
            "T"    : thing.tid,
            "t"    : ms_since_process_launch,
            "args" : self._prepare_args(thing)
        }))

    def _create_socket(self):
        """ Allocates a new socket and prepares it for communicating with the host """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        # Prepare the result server to accept data in BSON format
        s.sendall("BSON\n")
        return s

    def _send_api_description(self, lookup_idx, thing):
        """ Describes the given API call to the host """
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
            "category" : self._api_category(thing),
            "args"     : self._api_args_description(thing)
        }))

    def _send_new_process(self, thing):
        """ Sends a notification about a new target process out there """
        pid = thing.pid
        lookup_idx = self.descriptions[pid].index("__process__")

        # Remember when this process was born
        self.launch_times[pid] = thing.timestamp
        # Describe the __process__ notification
        self.sockets[pid].sendall(BSON.encode({
            "I"        : lookup_idx,
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
        filetime = _filetime_from_timestamp(thing.timestamp)
        # Get process name (aka module path)
        module = _proc_name_from_pid(pid)
        self.sockets[pid].sendall(BSON.encode({
            "I"    : lookup_idx,
            "T"    : thing.tid,
            "t"    : 0,
            "args" : [
                1,
                0,
                # TimeLow (first 32bits) and TimeHigh (last 32bits)
                filetime & 0xffffffff, filetime >> 32,
                thing.pid, thing.ppid,
                # ModulePath
                module
            ]
        }))

    def _prepare_args(self, thing):
        # First two "arguments" are always is_success and retval
        result = [
            self._verify_is_success(thing),
            thing.retval
        ]
        return result + thing.args

    def _verify_is_success(self, thing):
        retval = thing.retval
        e = self.human_readable_explanations
        if thing.api not in e: # fallback to success
            return 1

        condition = e[thing.api]["is_success_condition"]
        result = eval(condition, {
            "retval" : retval
        })
        return 1 if result else 0

    def _api_category(self, thing):
        # FIXME(rodionovd): I'm bad at naming
        e = self.human_readable_explanations
        api = thing.api
        if api not in e: # fallback
            return "unknown"
        return e[api]["category"]

    def _api_args_description(self, thing):
        # FIXME(rodionovd): I'm bad at naming
        e = self.human_readable_explanations
        api = thing.api
        # First two "arguments" are always these
        description = ["is_success", "retval"]
        if api in e:
            description += e[api]["args"]
        else: # fallback to arg0, arg1, ..., argN
            for arg_idx in range(0, len(thing.args)):
                description += ["arg%d" % arg_idx]
        return description

    def _load_human_readable_explanations(self):
        try:
            with open(_description_file_path(), "r") as f:
                self.human_readable_explanations = json.load(f)
        except: # TODO(rodionovd): differentiate exceptions and log errors
            self.human_readable_explanations = {}


def _proc_name_from_pid(pid):
    """ Parses `ps` output for the given PID """
    try:
        ps_output = check_output(["/bin/ps", "-p", str(pid), "-o", "comm"])
        # The first line of an output is reserved for `ps` headers and the
        # second one contains a process path
        return ps_output.split("\n")[1]
    except CalledProcessError:
        return "unknown"


def _filetime_from_timestamp(ts):
    """ See filetimes.py for details """
    # Timezones are hard, sorry
    dt = datetime.fromtimestamp(ts)
    delta_from_utc = dt - datetime.utcfromtimestamp(ts)
    return dt_to_filetime(dt, delta_from_utc)


def _description_file_path():
    return path.join(path.dirname(path.abspath(__file__)), "apis.json")
