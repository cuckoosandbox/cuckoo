#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import sys
import socket
import logging
import xmlrpclib

from datetime import datetime
from pkgutil import iter_modules
from traceback import format_exc
from lib.common.config import Config
from lib.common.results import NetlogHandler
from lib.core.constants import PATHS
from lib.core.packages import choose_package, Package, Auxiliary

from modules import auxiliary

class Macalyzer:
	"""Cuckoo OS X analyser.
	"""

	log = logging.getLogger()

	def __init__(self, aConfig=None):
		self.config = aConfig

	def _bootstrap(self):
		self._create_result_folders();
		self._setup_logging()
		self._detect_target()

	def run(self):
		"""Run analysis.
		"""
		self._bootstrap()

		self.log.debug("Starting analyzer from %s", os.getcwd())
		self.log.debug("Storing results at: %s", PATHS["root"])

		aux = _setup_auxiliary_modules(self.log)
		package = self._setup_analysis_package()

		if self.config.clock:
			self._setup_machine_time(self.config.clock)
		self._analysis(package)

		_shutdown_auxiliary_modules(aux, self.log)
		return self._complete()

	def _complete(self):
		return True

	#
	# Implementation details
	#

	def _create_result_folders(self):
		for name, folder in PATHS.items():
			if os.path.exists(folder):
				continue
			try:
				os.makedirs(folder)
			except OSError:
				pass

	def _setup_logging(self):
		""" Initialize logger. """
		logger = logging.getLogger()
		formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
		sh = logging.StreamHandler()
		sh.setFormatter(formatter)
		logger.addHandler(sh)

		nh = NetlogHandler()
		nh.setFormatter(formatter)
		logger.addHandler(nh)
		logger.setLevel(logging.DEBUG)

	def _detect_target(self):
		if self.config.category == "file":
			self.target = os.path.join("/tmp/",
			                           str(self.config.file_name))
		else: # It's not a file, but a URL
			self.target = self.config.target

	def _setup_analysis_package(self):
		pkg = None
		if self.config.package:
			pkg = self.config.package
		else:
			self.log.debug("No analysis package specified, trying to detect it"
			               " automagically.")
			if self.config.category != "file":
				pkg = "url"
			else:
				pkg = choose_package(self.config.file_type,
				                     self.config.file_name)
		if not pkg:
			raise Exception("No valid package available for file type: "
			                "{0}".format(self.config.file_type))
		# Importing the selected analysis package
		package_name = "modules.packages.%s" % pkg
		try:
			__import__(package_name, globals(), locals(), ["foo"], -1)
		except ImportError:
			raise Exception("Unable to import package \"{0}\": it does not "
			                "exist.".format(package_name))
		try:
			package_class = Package.__subclasses__()[0]
		except IndexError as e:
			raise Exception("Unable to select package class (package={0}): "
			                "{1}".format(package_name, e))

		options = self.config.get_options()
		timeout = self.config.timeout
		return package_class(target=self.target, options=options, timeout=timeout)

	def _setup_machine_time(self, clock_str, actually_change_time=True):
		clock = datetime.strptime(clock_str, "%Y%m%dT%H:%M:%S")
		# NOTE: On OS X there's `date` utility that accepts
		# new date/time as a string of the folowing format:
		# {month}{day}{hour}{minute}{year}.{ss}
		# where every {x} is a 2 digit number.

		cmd = "sudo date {0}".format(clock.strftime("%m%d%H%M%y.%S"))
		# TODO(rodionovd): patch sudoers for nopassword `sudo date`
		# if actually_change_time:
		# 	os.system(cmd)
		return cmd

	def _analysis(self, package):
		# self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# self.socket.connect((self.config.ip, self.config.port))
		# self.socket.sendall("BSON\n")

		log_entries = package.start()
		for entry in log_entries:
			self._send_to_host(entry)

	def _send_to_host(self, log_entry):
		# self.socket.sendall(log_entry)
		if None:
			self.log.error("The requested analysis type is not available (yet).")
		else:
			self.log.info(log_entry)


def _setup_auxiliary_modules(logger):
	Auxiliary()
	prefix = auxiliary.__name__ + "."
	for loader, name, ispkg in iter_modules(auxiliary.__path__, prefix):
		if ispkg:
			continue
		# Import auxiliary modules
		try:
			__import__(name, globals(), locals(), ["dummy"], -1)
		except ImportError:
			logger.warning("Unable to import the auxiliary module "
			               "\"{0}\": {1}".format(name, e))
	# Walk through the available auxiliary modules
	aux_enabled = []
	for module in Auxiliary.__subclasses__():
		try:
			aux = module(self.config.get_options())
			aux.start()
		except (NotImplementedError, AttributeError):
			logger.warning("Auxiliary module %s was not implemented",
			               aux.__class__.__name__)
			continue
		except Exception as e:
			logger.warning("Cannot execute auxiliary module %s: %s",
			               aux.__class__.__name__, e)
			continue
		finally:
			self.log.debug("Started auxiliary module %s", aux.__class__.__name__)
			aux_enabled.append(aux)
	return aux_enabled

def _shutdown_auxiliary_modules(aux, logger):
	for a in aux:
		try:
			a.stop()
		except (NotImplementedError, AttributeError):
			continue
		except Exception as e:
			logger.warning("Cannot terminate auxiliary module %s: %s",
			               aux.__class__.__name__, e)




if __name__ == "__main__":
	success = False
	error = ""

	try:
		config = Config(cfg="analysis.conf")
		analyzer = Macalyzer(config)
		success = analyzer.run()

	except KeyboardInterrupt:
		error = "Keyboard Interrupt"

	except Exception as e:
		error_exc = format_exc()
		error = str(e)
		if len(analyzer.log.handlers):
			analyzer.log.exception(error_exc)
		else:
			sys.stderr.write("{0}\n".format(error_exc))
	# Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
	finally:
		# Establish connection with the agent XMLRPC server.
		server = xmlrpclib.Server("http://127.0.0.1:8000")
		server.complete(success, error, PATHS["root"])
