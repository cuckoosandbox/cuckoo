#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest
from sets import Set

from common import DtraceTestCase
from analyzer.darwin.lib.dtrace.ipconnections import *

class TestIpconnections(DtraceTestCase):

	def test_ipconnections_udp(self):
		# given
		expected = ('127.0.0.1', # host
		            53,          # port
		            'UDP')       # protocol
		output = []
		# when
		for connection in ipconnections(self.current_target()):
			output.append(connection)
		# then
		assert len(output) == 1
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		assert len(matched) == 1

	def test_ipconnections_tcp(self):
		# given
		expected = ('127.0.0.1', # host
		            80,          # port
		            'TCP')       # protocol
		output = []
		# when
		for connection in ipconnections(self.current_target()):
			output.append(connection)
		# then
		assert len(output) == 1
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		assert len(matched) == 1

	def test_ipconnections_tcp_with_timeout(self):
		# given
		expected = ('127.0.0.1', # host
		            80,          # port
		            'TCP')       # protocol
		pids = Set()
		output = []
		# when
		for connection in ipconnections(self.current_target(), timeout=1):
			output.append(connection)
			pids.add(connection.pid)
		# then
		assert len(pids) == 1
		assert len(output) == 1
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		assert len(matched) == 1

	def test_ipconnections_empty(self):
		# given
		output = []
		# when
		for connection in ipconnections(self.current_target()):
			output.append(connection)
		# then
		assert len(output) == 0

	def test_ipconnections_target_with_args(self):
		# given
		expected = ('127.0.0.1', # host
		            80,          # port
		            'TCP')       # protocol
		args = ["127.0.0.1"]
		output = []
		# when
		for connection in ipconnections(self.current_target(), args=args):
			output.append(connection)
		# then
		assert len(output) == 1
		matched = [x for x in output if
			(x.remote, x.remote_port, x.protocol) == expected]
		assert len(matched) == 1

if __name__ == '__main__':
	unittest.main()
