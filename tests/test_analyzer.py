#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest
from analyzer.darwin.lib.core.osx import set_wallclock

class TestAnalyzer(unittest.TestCase):

    def test_set_wallclock(self):
        # given
        clock_str = "20151203T15:23:43"
        # when
        result = set_wallclock(clock_str, just_testing=True)
        # then
        self.assertEqual(result, "sudo date 1203152315.43")
