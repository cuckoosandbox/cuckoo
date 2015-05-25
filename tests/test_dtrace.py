#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import sys
import unittest
import subprocess

from analyzer.darwin.lib.dtrace.dtruss import *
from analyzer.darwin.lib.dtrace.ipconnections import *

TESTS_DIR = os.path.dirname(os. path.abspath(__file__))

class TestDtrace(unittest.TestCase):

	def setUp(self):
		build_target(self._testMethodName)

	def tearDown(self):
		cleanup_target(self._testMethodName)

	def current_target(self):
		return TESTS_DIR + "/assets/" + self._testMethodName

	def test_dtruss_helloworld(self):
		# given
		expected_syscall = ('write_nocancel', ['0x1', 'Hello, world!\\n\\0', '0xE'], 14, 0)
		# when
		output = dtruss(self.current_target())
		#then
		self.assertIn(expected_syscall, output)
		self.assertEqual(sum(x.name == "write_nocancel" for x in output), 1)

	def test_dtruss_specific_syscall(self):
		# given
		expected_syscall = ('write_nocancel', ['0x1', 'Hello, dtruss!\\n\\0', '0xF'], 15, 0)
		# when
		output = dtruss(self.current_target(), None, "write_nocancel")
		# then
		self.assertIn(expected_syscall, output)
		self.assertEqual(len(output), 1)

	def test_dtruss_timeout(self):
		# given
		expected_syscall = ('write', ['0x1', 'Hello, world!\\n\\0', '0xE'], 14, 0)
		# when
		output = dtruss(self.current_target(), 1)
		#then
		self.assertIn(expected_syscall, output)
		self.assertEqual(sum(x.name == "write" for x in output), 1)

	def test_ipconnections_udp(self):
		# given
		expected = ('127.0.0.1', # host
		            53,          # port
		            'UDP')       # protocol
		# when
		output = ipconnections(self.current_target())
		# then
		self.assertEqual(len(output), 1)
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		self.assertEqual(len(matched), 1)

	def test_ipconnections_tcp(self):
		# given
		expected = ('127.0.0.1', # host
		            80,          # port
		            'TCP')       # protocol
		# when
		output = ipconnections(self.current_target())
		# then
		self.assertEqual(len(output), 1)
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		self.assertEqual(len(matched), 1)

	def test_ipconnections_tcp_with_timeout(self):
		# given
		expected = ('127.0.0.1', # host
		            80,          # port
		            'TCP')       # protocol
		# when
		output = ipconnections(self.current_target(), 1)
		# then
		self.assertEqual(len(output), 1)
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		self.assertEqual(len(matched), 1)


	def test_ipconnections_empty(self):
		# when
		output = ipconnections(self.current_target())
		# then
		self.assertEqual(len(output), 0)

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

if __name__ == '__main__':
	unittest.main()
