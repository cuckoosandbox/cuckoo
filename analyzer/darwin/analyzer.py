#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

class Macalyser:
	"""Cuckoo OS X analyser.
	"""
	
	logger = 0
	injector = ""
	target = ""
	target_artefacts = []
	config= []
	uses_proc_monitor = False

	def __init__(self):
		# setup logging
		# parse the config
		# figure out what the target is
		pass

	def run(self):
		# package = analysis_package_for_current_target()
		# aux = setup_auxiliary_modules()
		#
		# setup_machine_time(self.config.datetime)
		# results = analysis(package)
		#
		# shutdown_auxiliary_modules(aux)
		# shutdown_spawned_modules(results.procs_still_alive)
		# complete()
		pass

	def complete(self):
		# upload_artefacts()
		# cleanup()
		pass

	#
	# Implementation details
	#
	def setup_loggin(self):
		pass

	def parse_config(self, config_name):
		pass

	def analysis_package_for_current_target(self):
		pass

	def setup_auxiliary_modules(self):
		pass

	def setup_machine_time(self, datetime):
		pass

	def analysis(self, package):
		pass

	def shutdown_auxiliary_modules(self, aux):
		pass

	def shutdown_spawned_processes(self, procs):
		pass

	def upload_artefacts(self):
		pass

	def cleanup(self):
		pass


if __name__ == "__main__":
	pass
