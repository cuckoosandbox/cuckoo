# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import logging
import StringIO
from lib.api import adb
from threading import Thread
from lib.common.results import NetlogFile
from lib.common.abstracts import Auxiliary
from lib.api.droidbot.dtypes import App, Device
from lib.api.droidbot.event import AppEventManager


log = logging.getLogger(__name__)

class DroidBot(Auxiliary, Thread):
	"""
	DroidBot module
	A robot which interact with Android automatically
	"""
	def __init__(self):
		"""
		initiate droidbot instance
		"""
		Thread.__init__(self)
		self.output_dir = os.path.abspath("droidbot_out")
		if not os.path.exists(self.output_dir):
			os.mkdir(self.output_dir)

		self.device = Device(self.output_dir)
		self.app_path = adb.getLastInstalledPackagePath()
		self.app = App(self.app_path, self.output_dir)

		self.event_manager = AppEventManager(device = self.device, app = self.app)

	
	def run(self):
		log.info("Starting DroidBot")
		while not self.device.is_foreground(self.app):
			log.info("Waiting for app to be executed")
			time.sleep(2)

		try:
			self.event_manager.start()
		except KeyboardInterrupt:
			pass

		return True

	def stop(self):
		self.device.disconnect()
		self.event_manager.stop()

		# upload droidbot output to host
		self.upload("droidbot_event.json", "event.json")
		self.upload("logcat.log", "logcat.log")
		log.info("Droidbot stopped")
		return


	def upload(self, out_file, remote_file):
		filename = os.path.join(self.output_dir, out_file)
		while not os.path.exists(filename):
			time.sleep(2)
		file = open(filename, "r")
		tmpio = StringIO.StringIO(file.read())
		nf = NetlogFile("logs/%s" % remote_file)

		for chunk in tmpio:
			nf.sock.sendall(chunk)

		nf.close()
		file.close()
