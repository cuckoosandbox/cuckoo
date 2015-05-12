#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import subprocess
import csv

# TODO(rodionovd): implement SysCall class (or named tuple?) and use them
# instead of tuples

def dtruss(target):
	"""Returns a list of syscalls made by a target.

	Every syscall is a tuple of the following format:
		(name, [arg0, arg1, arg2, ...], return_code, errno)
	Everything in this tuple is a string.
	"""
	cmd = ["sudo", "/usr/bin/dtruss", target]
	output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).splitlines()

	# We're only interested in dtruss' output, not the target's: remove anything
	# before the dtruss header
	dtruss_header_idx = output.index("SYSCALL(args) \t\t = return")
	del output[:dtruss_header_idx+1]

	return _parse_dtruss_output(output)

#
# Parsing implementation details
#
# dtruss' output format:
# SYSCALL(arg0, arg1, arg2, ..) 		 = result, errno
#

def _parse_dtruss_output(lines):
	"""Parses dtruss' output into separate syscalls tuples
	"""
	# Remove empty lines first
	lines = filter(None, lines)
	results = []
	for cmd in lines:
		name   = _syscall_name_from_dtruss_output(cmd)
		args   = _syscall_args_from_dtruss_output(cmd)
		result = _syscall_result_from_dtruss_output(cmd)
		errno  = _syscall_errno_from_dtruss_output(cmd)

		results.append((name, args, result, errno))

	return results

def _syscall_name_from_dtruss_output(output_line):
	length = output_line.index('(')
	return output_line[:length]

def _syscall_args_from_dtruss_output(output_line):
	args_string = output_line[output_line.index('(')+1 : output_line.rfind(")")]
	args_string = args_string.replace('\0', '')
	# --HACK--
	# I noticed that a syscall arguments look like a CSV string,
	# so let's just use the built-in csv module for parsing them.
	# Why not just split(',') it? Because some arguments (strings)
	# may contain commas as well -- and I don't want to deal with this.
	#
	# But! csv won't handle fields with commas inside them without
	# skipinitialspace set to True
	parsed_rows = list(csv.reader([args_string], skipinitialspace=True))
	# We have only one row here
	args = parsed_rows[0]
	# Remove trailing zeros from strings
	for item in args:
		item = item.replace('\0', '')
	return args

def _syscall_result_from_dtruss_output(output_line):
	result_errno_tag = "\t\t = "
	from_idx = output_line.rfind(result_errno_tag) + len(result_errno_tag)
	tail = output_line[from_idx :].strip()
	return tail.split(' ')[0]

def _syscall_errno_from_dtruss_output(output_line):
	result_errno_tag = "\t\t = "
	from_idx = output_line.rfind(result_errno_tag) + len(result_errno_tag)
	tail = output_line[from_idx :].strip()
	errno = tail.split(' ')[1]
	# Also remove 'Err#' prefix from errno if any
	if errno.startswith('Err#'):
		errno = errno[len('Err#'):]
	return errno

if __name__ == "__main__":
	pass
