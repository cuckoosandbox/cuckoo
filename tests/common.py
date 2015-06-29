#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import unittest
import subprocess

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


class DtraceTestCase(unittest.TestCase):
    def setUp(self):
        build_target(self._testMethodName)

    def tearDown(self):
        cleanup_target(self._testMethodName)

    def current_target(self):
        return TESTS_DIR + "/assets/" + self._testMethodName


def build_target(target):
    # clang -arch x86_64 -o $target_name $target_name.c
    output = executable_name_for_target(target)
    source = sourcefile_name_for_target(target)
    subprocess.check_call(["clang", "-arch", "x86_64", "-O0", "-o", output, source])


def cleanup_target(target):
    os.remove(executable_name_for_target(target))


def sourcefile_name_for_target(target):
    return "%s/assets/%s.c" % (TESTS_DIR, target)


def executable_name_for_target(target):
    return "%s/assets/%s" % (TESTS_DIR, target)
