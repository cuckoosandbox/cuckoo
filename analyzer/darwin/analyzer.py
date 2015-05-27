#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import sys
import pkgutil
import logging
import traceback

from time import sleep
from datetime import datetime
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
		"""
		"""
		self._bootstrap()

		self.log.debug("Starting analyzer from %s", os.getcwd())
		self.log.debug("Storing results at: %s", "FOOBAR")

		aux_enabled, aux_all = self._setup_auxiliary_modules()
		package = self._setup_analysis_package()

		self._setup_machine_time(self.config.clock)
		self.results = self._analysis(package)

		self._shutdown_auxiliary_modules(aux_enabled, aux_all)
		self._complete()

	def _complete(self):
		self._upload_results()
		self._cleanup()

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
		formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
		# Setup a stream handler
		sh = logging.StreamHandler()
		sh.setFormatter(formatter)
		self.log.addHandler(sh)
		# Setup a netlog handler
		nh = NetlogHandler()
		nh.setFormatter(formatter)
		self.log.addHandler(nh)
		self.log.setLevel(loggin.DEBUG)


	def _detect_target(self):
		if self.config.category == "file":
			self.target = os.path.join(os.environ["TEMP"] + os.sep,
			                           str(self.config.file_name))
		else: # It's not a file, but a URL
			self.target = self.config.target


	def _setup_analysis_package(self):
		# Figuring out what package to use
		pkg = None
		if self.config.package:
			pkg = self.config.package
		else:
			self.log.debug("No analysis package specified, trying to detect it",
			               "it automagically.")
			if self.config.category != "file":
				pkg = "safari"
			else:
				pkg = choose_package(FILE_TYPE, FILE_NAME)
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
		Package()
		try:
			package_class = Package.__subclasses__()[0]
		except IndexError as e:
			raise Exception("Unable to select package class (package={0}): {1}".format(package_name, e))
		return package_class(self.config.get_options())


	def _setup_auxiliary_modules(self):
		# Initialize Auxiliary modules
		Auxiliary()
		prefix = auxiliary.__nam__name__ + "."
		for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
			if ispkg:
				continue
			# Import auxiliary modules
			try:
				__import__(name, globals(), locals(), ["dummy"], -1)
			except ImportError:
				self.log.warning("Unable to import the auxiliary module "
				                 "\"{0}\": {1}".format(name, e))
		# Walk through the available auxiliary modules
		aux_enabled, aux_available = [], []
		for module in Auxiliary.__subclasses__():
			try:
				aux = module(self.config.get_options())
				aux_available.append(aux)
				aux.start()
			except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            aux.__class__.__name__)
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            aux.__class__.__name__, e)
                continue
            finally:
                log.debug("Started auxiliary module %s",
                          aux.__class__.__name__)
                aux_enabled.append(aux)

		return (aux_enabled, aux_available)


	def _setup_machine_time(self, clock_str, actually_change_time=True):
		clock = datetime.strptime(clock_str, "%Y%m%dT%H:%M:%S")
		# NOTE: On OS X there's `date` utility that accepts
		# new date/time as a string of the folowing format:
		# {month}{day}{hour}{minute}{year}.{ss}
		# where every {x} is a 2 digit number.
		cmd = "date {0}".format(clock.strftime("%m%d%H%M%y.%S"))
		if actually_change_time:
			os.system(cmd)
		return cmd


	def _analysis(self, package):
		package.start(self.target)
		timer = 0
		while timer <= int(self.config.timeout):
			sleep(1)
			timer += 1
			if not package.check():
				break
		return package.finish()


	def _shutdown_auxiliary_modules(self, aux_enabled, aux_all):
		for a in aux_enabled:
			try:
				a.stop()
		except (NotImplementedError, AttributeError):
			continue
		except Exception as e:
			log.warning("Cannot terminate auxiliary module %s: %s",
						aux.__class__.__name__, e)
		for a in aux_all:
			try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary "
                            "module %s: %s", aux.__class__.__name__, e)


	def _upload_results(self):
		pass


	def _cleanup(self):
		pass

if __name__ == "__main__":
	success = False
	error = ""

	try:
		config = Config(cgf="analysis.conf")
		analyzer = Macalyzer(config)
		success = analyzer.run()

	except KeyboardInterrupt:
		error = "Keyboard Interrupt"

	except Exception as e:
		error_exc = traceback.format_exc()
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
