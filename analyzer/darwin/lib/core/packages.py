#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from ..dtrace.dtruss import dtruss
from ..dtrace.apicalls import apicalls
from ..dtrace.ipconnections import ipconnections

def choose_package(file_type, file_name):
    if "Bourne-Again" in file_type or "bash" in file_type:
        return "bash"
    elif "Mach-O" in file_type and "executable" in file_type:
        return "macho"
    else:
        return None

class Package(object):
    """ Base analysis package """

    def __init__(self, **kwargs):
        if "target" in kwargs:
            self.target = kwargs["target"]
        else:
            raise Exception("Package(): `target` argument is required")
        if "options" in kwargs:
            self.options = kwargs["options"]
        else:
            self.options = []
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]

        self.args = []

    def start(self):
        """ Runs an analysis process.
        This function is a generator of log entries to send to the host.
        """
        raise NotImplementedError

    #
    # start() demo implementations
    #

    def _start_dtruss(self):
        for call in dtruss(self.target, args=self.args, timeout=self.timeout):
            yield "[%d @ %d]: %s(%s) -> %s" % (call.pid, call.timestamp,
                                               call.name, call.args,
                                               call.result)

    def _start_ipconnections(self):
        for conn in ipconnections(self.target, args=self.args, timeout=self.timeout):
            yield "[IP]: %s:%d --[%s]--> %s:%d" % (conn.host, conn.host_port,
                                                   conn.protocol,
                                                   conn.remote, conn.remote_port)

    def _start_apicalls(self):
        if "run_as_root" in self.options:
            root_mode = True
        else:
            root_mode = False
        for call in apicalls(self.target, args=self.args, timeout=self.timeout, run_as_root=root_mode):
            yield "[%d @ %d]: %s(%s) -> %s" % (call.pid, call.timestamp,
                                               call.api, call.args,
                                               str(call.retval))

class Auxiliary(object):
    def __init__(self, options=[]):
        self.options = options

    def start(self):
        pass

    def stop(self):
        pass
