#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

def choose_package(file_type, file_name):
    pass


class Package(object):
    """ Base analysis package """
    state = "idle" # also "in progress" and "complete"

    def __init__(self, options):
        self.options = options

    def start(self, target):
        self.state = "in progress"
        raise NotImplementedError
        self.state = "complete"

    def check(self):
        return self.state != "complete"

    def finish(self):
        """ Returns data to upload to a host """
        raise NotImplementedError

class Auxiliary(object):
    def __init__(self, options):
        self.options = options
