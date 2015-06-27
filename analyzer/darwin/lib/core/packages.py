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

    def __init__(self, target, host, **kwargs):
        if not target or not host:
            raise Exception("Package(): `target` and `host` arguments are required")

        self.host = host
        self.target = target
        # Any analysis options?
        if "options" in kwargs:
            self.options = kwargs["options"]
        else:
            self.options = []
        # A timeout for analysis
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
        # Command-line arguments for the target.
        # TODO(rodionovd): add an option to specify arguments
        self.args = []
        # Choose an analysis method
        if "method" in self.options:
            self.method = self.options["method"]
        else: # fallback
            self.method = "apicalls"
        # Should our target be launched as root or not
        if "run_as_root" in self.options:
            self.run_as_root = self.options["run_as_root"]
        else:
            self.run_as_root = False

    def prepare(self):
        """ Preparation routine. Do anything you want here. """
        pass

    def start(self):
        """ Runs an analysis process.
        This function is a generator.
        """
        self.prepare()

        if self.method == "apicalls":
            self.apicalls_analysis()
        else:
            raise Exception("Unsupported analysis method")

    def apicalls_analysis(self):
        kwargs = {
            'args' : self.args,
            'timeout' : self.timeout,
            'run_as_root' : self.run_as_root
        }
        for call in apicalls(self.target, **kwargs):
            self.host.send_api(call)

class Auxiliary(object):
    def __init__(self, options=[]):
        self.options = options

    def start(self):
        pass

    def stop(self):
        pass
