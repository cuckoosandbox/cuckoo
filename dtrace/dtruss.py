#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
from csv import reader
from sys import argv
from collections import namedtuple
from subprocess import check_call
from tempfile import NamedTemporaryFile

syscall = namedtuple("syscall", "name args result errno")

def dtruss(target, timeout=None, syscall=None):
	"""Returns a list of syscalls made by a target.

	Every syscall is a named tuple with the following properties:
	name (string), args (list of strings), result (int), errno (int).
	"""
	file = NamedTemporaryFile()
	timeout_value = timeout if timeout != None else -1
	if syscall is None:
		cmd = ["sudo", _dtruss_script_path(),
		       "-W", file.name,
		       "-K", str(timeout_value),
		       _sanitize_target_path(target)]
	else:
		cmd = ["sudo", _dtruss_script_path(),
		       "-W", file.name,
		       "-t", syscall,
		       "-K", str(timeout_value),
		       _sanitize_target_path(target)]

	with open(os.devnull, "w") as f:
		check_call(cmd, stdout=f, stderr=f)
	output = file.read().splitlines()
	file.close()

	# We're only interested in dtruss' output, not the target's: remove anything
	# before the dtruss header
	dtruss_header_idx = output.index("SYSCALL(args) \t\t = return")
	del output[:dtruss_header_idx+1]

	return _parse_dtruss_output(output)


def _sanitize_target_path(path):
    return path.replace(" ", "\\ ")

def _dtruss_script_path():
    return os.path.dirname(os.path.abspath(__file__)) + "/dtruss.sh"
#
# Parsing implementation details
#
# dtruss' output format:
# SYSCALL(arg0, arg1, arg2, ..) 		 = result, errno
#

def _parse_dtruss_output(lines):
	"""Turns non-empty strings from dtruss output into syscall tuples
	"""
	return map(_parse_syscall, filter(None, lines))

def _parse_syscall(string):
	name   = _syscall_name_from_dtruss_output(string)
	args   = _syscall_args_from_dtruss_output(string)
	# Result and errno are either decimal or hex numbers
	result = int(_syscall_result_from_dtruss_output(string), 0)
	errno  = int(_syscall_errno_from_dtruss_output(string), 0)

	return syscall(name=name, args=args, result=result, errno=errno)

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
	parsed_rows = list(reader([args_string], skipinitialspace=True))
	# We have only one row here
	args = parsed_rows[0]
	# Remove trailing zeros from strings
	return list(x.replace('\0', '') for x in args)

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
	if len(argv) < 2:
		print "Usage: %s <target> [syscall]" % argv[0]
		exit(0)

	target = argv[1]
	optional_probe = argv[2] if len(argv) > 2 else None

	for syscall in dtruss(target, optional_probe):
		print "%s(%s) -> %#x %s" % (
			syscall.name,
			", ".join(syscall.args) if len(syscall.args) > 0 else "",
			syscall.result,
			"(errno = %s)" % syscall.errno if syscall.errno != 0 else ""
		)
