#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest
from analyzer.darwin.analyzer import Macalyzer

class TestAnalyzer(unittest.TestCase):

    def test_set_machine_time(self):
        # given
        clock_str = "20151203T15:23:43"
        # when
        result = Macalyzer()._setup_machine_time(clock_str, dont_really_make_changes=True)
        # then
        assert result == "sudo date 1203152315.43"
