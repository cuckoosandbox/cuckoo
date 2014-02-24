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
import json

def main():
	# Pre-defined static URL
	pre_def_url = "http://127.0.0.1:8090/tasks/create/file"


	parser = argparse.ArgumentParser()
	parser.add_argument("target", type=str, help="Path to the file or folder to analyze")
	parser.add_argument("--timeout", type=int, action="store", default=0, help="Specify an analysis timeout", required=False)
	parser.add_argument("--priority", type=int, action="store", default=1, help="Specify a priority for the analysis represented by an integer", required=False)
	parser.add_argument("--memory", type=int, action="store", default=0, help="Specify a memory dump for the analysis represented by an integer", required=False)
	
	
	# If User defied server URL, --server is optional
	if "127.0.0.1" in pre_def_url:
		parser.add_argument("--server", type=str, action="store", help="Specify a API server address to send request to in format (IP:PORT)", required=True)
	else:
		parser.add_argument("--server", type=str, action="store", help="Specify a API server address to send request to in format (IP:PORT)", required=False)

	
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

	result = json.loads(raw_request.text)

	if "task_id" in result:
		print "Success: File %s added as task with ID %s" % (args.target, result["task_id"])
	else:
		sys.exit("Error submitting %s " % args.target)


if __name__ == "__main__":
	main()
