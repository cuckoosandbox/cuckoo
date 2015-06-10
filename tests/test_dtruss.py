#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest
from sets import Set

from common import DtraceTestCase
from analyzer.darwin.lib.dtrace.dtruss import *

class TestDtruss(DtraceTestCase):

	def test_dtruss_helloworld(self):
		# given
		expected_syscall = 'write_nocancel'
		expected_args = [1, 'Hello, world!\n', 0xE]
		expected_result = 14
		expected_errno =  0
		output = []
		# when
		for call in dtruss(self.current_target()):
			output.append(call)
		# then
		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1

	def test_dtruss_specific_syscall(self):
		# given
		expected_syscall = 'write_nocancel'
		expected_args = [1, 'Hello, dtruss!\n', 0xF]
		expected_result = 15
		expected_errno =  0
		output = []
		# when
		for call in dtruss(self.current_target(), syscall="write_nocancel", run_as_root=False):
			output.append(call)
		# then
		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1

	def test_dtruss_timeout(self):
		# given
		expected_syscall = 'write'
		expected_args = [1, 'Hello, world!\n', 0xE]
		expected_result = 14
		expected_errno =  0
		output = []
		# when
		for call in dtruss(self.current_target(), timeout=2, run_as_root = True):
			output.append(call)
		# then
		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1
		assert sum(x.name == "write" for x in output) == 1

	def test_dtruss_with_args(self):
		# given
		expected_syscall = 'write_nocancel'
		expected_args = [1, 'Hello, WoR1D!\n', 0xE]
		expected_result = 14
		expected_errno =  0
		args = ["WoR1D", "-k", "foobar"]
		output = []
		# when
		for call in dtruss(self.current_target(), args=args):
			output.append(call)
		# then
		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1

	def test_dtruss_root(self):
		# given
		expected_syscall = 'write_nocancel'
		expected_args = [1, 'Hello, r00t!\n', 0xD]
		expected_result = 0xD
		expected_errno =  0
		pids = Set()
		output = []
		# when
		for call in dtruss(self.current_target(), run_as_root = True):
			output.append(call)
			pids.add(call.pid)
		# then
		assert len(pids) == 1

		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1

	def test_dtruss_non_root(self):
		# given
		expected_syscall = 'write_nocancel'
		expected_args = [1, 'Hello, user!\n', 0xD]
		expected_result = 0xD
		expected_errno =  0
		pids = Set()
		output = []
		# when
		for call in dtruss(self.current_target()):
			output.append(call)
			pids.add(call.pid)
		# then
		assert len(pids) == 1

		matched = [x for x in output if x.name == expected_syscall and x.args == expected_args and x.result == expected_result and x.errno == expected_errno]

		assert len(matched) == 1


	def test_dtruss_children(self):
		# given
		expected_child_syscall  = ("write", [1, "Hello from child!\n", 18], 18)
		expected_parent_syscall = ("write", [1, "Hello, I'm parent!\n", 19], 19)
		pids = Set()
		output = []
		# when
		for call in dtruss(self.current_target()):
			output.append(call)
			pids.add(call.pid)
		# then
		assert len(pids) == 2

		matched_child = [x for x in output if (x.name, x.args, x.result) == expected_child_syscall]
		matched_parent = [x for x in output if (x.name, x.args, x.result) == expected_parent_syscall]

		assert len(matched_child) == 1
		assert len(matched_parent) == 1
		assert (matched_parent[0].pid < matched_child[0].pid)
