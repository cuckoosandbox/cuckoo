#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# Written by Silas Cutler <Silas.Cutler@BlackListThisDomain.com>
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import requests
import argparse
import os
import sys
import re

def main():
	# Pre-defined static URL
	pre_def_url = "http://127.0.0.1:8080/submit"

	parser = argparse.ArgumentParser()
	parser.add_argument("target", type=str, help="Path to the file or folder to analyze")
	parser.add_argument("--timeout", type=int, action="store", default=0, help="Specify an analysis timeout", required=False)
	parser.add_argument("--priority", type=int, action="store", default=1, help="Specify a priority for the analysis represented by an integer", required=False)
	parser.add_argument("--memory", type=int, action="store", default=0, help="Specify a memory dump for the analysis represented by an integer", required=False)
	
	
	# If User defied server URL, --server is optional
	if "127.0.0.1" in pre_def_url:
		parser.add_argument("--server", type=str, action="store", help="Specify a server to send request to in format (IP:PORT)", required=True)
	else:
		parser.add_argument("--server", type=str, action="store", help="Specify a server to send request to in format (IP:PORT)", required=False)

	
	try:
		args = parser.parse_args()
	except IOError as e:
		parser.error(e)
		return False
	
	if not os.path.isfile(args.target):
		sys.exit("File Doesn't exist")
	
	if args.server and ":" in args.server:
		url = "http://%s/submit" % args.server
	else:
		url = pre_def_url
	
	r_payload = {
		'file': open(args.target, "rb"), 
		'filename':"Remote_Upload" ,
		}
	r_data = {
		'timeout': args.timeout,
		'priority': args.priority,
		'package' :"",
		'options' :"",
		'machine': "",
		'memory' : args.memory
	}
		
	try:
		raw_request = requests.post(url, files=r_payload, data=r_data)
	except:
		sys.exit("Failed to Post file")


	if "The server encountered an internal error while submitting" in raw_request.text:
		sys.exit("Error submitting %s " % args.target)
	elif "was submitted for analysis with Task ID" in raw_request.text:
		match_pattern = 'view.([0-9]+)"'
		task_id = re.search(match_pattern, raw_request.text, re.M|re.I|re.S)
		if task_id.group(1).isdigit():
			print "Success: File %s added as task with ID %s" % (args.target, task_id.group(1))
		else:
			print "Success: File %s added as task" % (args.target)
	else:
		print "Unknown error"

if __name__ == "__main__":
	main()
