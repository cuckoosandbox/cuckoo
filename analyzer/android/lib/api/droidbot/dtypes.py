# Copyright (C) 2015 Yuanchun Li
# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# utils for setting up Android environment and sending events

import os
import re
import time
import logging
import subprocess
from lib.api import adb
from lib.core.config import Config


DEFAULT_NUM = "1234567890"
DEFAULT_CONTENT = "Hello world!"

class Device(object):
	"""
	this class describes a connected device
	"""
	def __init__(self, output_dir = None):
		self.logger = logging.getLogger(__name__)
		self.setting = {}
		self.display_info = None

		self.output_dir = output_dir
		if self.output_dir == None:
			self.output_dir = os.path.abspath("droidbot_out")
		if not os.path.exists(self.output_dir):
			os.mkdir(self.output_dir)
		self.get_display_info()

		self.logcat = self.redirect_logcat()

		self.logger.info("DroidBot is loaded !")


	def redirect_logcat(self, output_dir = None):
		if output_dir is None:
			output_dir = self.output_dir

		logcat_file = open(os.path.join(self.output_dir, "logcat.log"), "w")

		import subprocess
		logcat = subprocess.Popen(["logcat", "-v", "threadtime"], stdin = subprocess.PIPE, stdout = logcat_file)

		return logcat

	def disconnect(self):
		"""
		disconnect the current device
		:return:
		"""
		self.logcat.terminate()


	def is_foreground(self, app):
		"""
		check if app is in foreground of device
		:param app: App
		:return: boolean
		"""
		if isinstance(app, str):
			package_name = app
		elif isinstance(app, App):
			package_name = app.get_package_name()
		else:
			return False

		focused_window_name = adb.getTopActivityName()
		if focused_window_name is None:
			return False
		return focused_window_name.startswith(package_name)

	def get_display_info(self):
		"""
		get device display information, including width, height and density
		:return: dict, display_info
		"""
		if self.display_info is None:
			self.display_info = adb.getDisplayInfo()
		return self.display_info

	def device_prepare():
		"""
		unlock screen
		skip first-use tutorials
		etc
		:return:
		"""

		#unlock screen
		adb.unlock()

	def receive_call(self, phone = DEFAULT_NUM):
		"""
		simulate a income phonecall
		:param phone: str, phone number
		:return:
		"""
		pass

	def cancel_call(self, phone = DEFAULT_NUM):
		"""
		cancel phonecall
		:param phone: str, phone number
		:return:
		"""
		pass

	def accept_call(self, phone = DEFAULT_NUM):
		"""
		accept phonecall
		:param phone: str, phone number
		:return:
		"""
		pass

	def call(self, phone = DEFAULT_NUM):
		"""
		simulate a outcome phonecall
		:param phone: str, phone number
		:return:
		"""
		call_intent = Intent(prefix = "start",
							 action = "android.intent.action.CALL",
							 data_uri = "tel:%s" % phone)
		return self.send_intent(intent = call_intent)

	def send_sms(self, phone = DEFAULT_NUM, content = DEFAULT_CONTENT):
		"""
		send a sms
		:param phone: str, phone number
		:param content: str, content of sms
		:return:
		"""
		send_sms_intent = Intent(prefix = "start",
								 action = "android.intent.action.SENDTO",
								 data_uri = "sms:%s" % phone,
								 extra_string = {"sms_body" : content},
								 extra_boolean = {"exit_on_sent" : "true"})
		self.send_intent(intent = send_sms_intent)
		time.sleep(2)
		adb.press('66')
		return True

	def receive_sms(self, phone = DEFAULT_NUM, content = DEFAULT_CONTENT):
		"""
		receive a SMS
		:param phone: str, phone number of sender
		:param content: str, content of sms
		:return:
		"""
		pass

	def set_gps(self, x, y):
		"""
		set GPS positioning to x,y
		:param x: float
		:param y: float
		:return:
		"""
		pass


	def get_setting(self):
		"""
		get device setting via adb
		"""
		db_name = "/data/data/com.android.providers.settings/databases/settings.db"
		system_settings = {}
		out = adb.shell("sqlite3 %s \"select * from %s\"" % (db_name, "system"))
		out_lines = out.splitlines()
		for line in out.splitlines():
			segs = line.split("|")
			if len(segs) != 3:
				continue
			system_settings[segs[1]] = segs[2]

		secure_settings = {}
		out = adb.shell("sqlite3 %s \"select * from %s\"" % (db_name, "secure"))
		out_lines = out.splitlines()
		for line in out_lines:
			segs = line.split("|")
			if len(segs) != 3:
				continue
			secure_settings[segs[1]] = segs[2]

		self.settings["system"] = system_settings
		self.settings["secure"] = secure_settings
		return self.settings

	def change_settings(self, table_name, name, value):
		"""
		dangerous method, by calling this, change settings.db in device
		be very careful for sql injection
		:param table_name: table name to work on, usually it is system or secure
		:param name: settings name to set
		:param value: settings value to set
		"""
		db_name = "/data/data/com.android.providers.settings/databases/settings.db"

		adb.shell("sqlite3 %s \"update %s set value='%s' where name='%s'" 
										% (db_name, table_name, value, name))
		return True

	def send_intent(self, intent):
		"""
		send an intent to device via am (ActivityManager)
		:param intent: instance of Intent
		:return:
		"""
		assert intent is not None
		cmd = intent.get_cmd()
		return adb.shell(cmd)

	def send_event(self, event):
		"""
		send one event to device
		:param event: the event to be sent
		:return:
		"""
		self.logger.info("Sending event: %s" % event)
		event.send(self)

	def start_app(self, app):
		"""
		start an app on the device
		:param app: instance of App, or str of package name
		:return:
		"""
		if isinstance(app, str):
			package_name = app
		elif isinstance(app, App):
			package_name = app.get_package_name()
			if app.get_main_activity():
				package_name = "/%s" % app.get_main_activity()
		else:
			self.logger.warning("Unsupported param " + app + " with type: ", type(app))
			return
		intent = Intent(suffix = package_name)
		self.send_intent(intent)

	def get_package_path(self, package_name):
		"""
		get installation path of a package (app)
		:param package_name:
		:return: package path of app in device
		"""
		dat = adb.shell("pm path %s" % package_name)
		package_path_RE = re.compile("^package:(.+)$")
		m = package_path_RE.match(dat)
		if m:
			path = m.group(1)
			return path.strip()
		return None

	def start_activity_via_monkey(self, package):
		"""
		use monkey to start activity
		"""
		cmd = "monkey"
		if package:
			cmd += " -p %s" % package
		out = adb.shell(cmd)
		if re.search(r"(Error)|(Cannot find 'App')", out, re.IGNORECASE | re.MULTILINE):
			raise RuntimeError(out)


	def get_current_state(self):
		pass

class App(object):
	"""
	this class describes an app
	"""
	def __init__(self, app_path, output_dir=None):
		"""
		create a App instance
		:param app_path: local file path of app
		:return:
		"""
		assert app_path is not None
		self.logger = logging.getLogger(__name__)

		self.app_path = app_path
		self.output_dir = output_dir
		
		config = Config(cfg="analysis.json")

		self.package_name = config.options["apk_entry"].split(":")[0]
		self.main_activity = config.options["apk_entry"].split(":")[1]
		self.possible_broadcasts = config.apk_possible_broadcasts
		try:
			self.possible_inputs = config.options["inputs"]
			if type(self.possible_inputs) != dict:
				self.possible_inputs = None
		except KeyError:
			self.possible_inputs = None

	def get_start_intent(self):
		"""
		get an intent to start the app
		:return: Intent
		"""
		package_name = self.package_name
		if self.main_activity:
			package_name += "/%s" % self.main_activity
		return Intent(suffix = package_name)

	def get_possible_broadcasts(self):
		return self.possible_broadcasts

	def get_possible_inputs(self):
		return self.possible_inputs

	def get_main_activity(self):
		return self.main_activity

	def get_package_name(self):
		return self.package_name


class Intent(object):
	"""
	this class describes a intent event
	"""
	def __init__(self, prefix="start", action=None, data_uri=None, mime_type=None, category=None,
				 component=None, flag=None, extra_keys=None, extra_string=None, extra_boolean=None,
				 extra_int=None, extra_long=None, extra_float=None, extra_uri=None, extra_component=None,
				 extra_array_int=None, extra_array_long=None, extra_array_float=None, flags=None, suffix=""):
		self.event_type = "intent"
		self.prefix = prefix
		self.action = action
		self.data_uri = data_uri
		self.mime_type = mime_type
		self.category = category
		self.component = component
		self.flag = flag
		self.extra_keys = extra_keys
		self.extra_string = extra_string
		self.extra_boolean = extra_boolean
		self.extra_int = extra_int
		self.extra_long = extra_long
		self.extra_float = extra_float
		self.extra_uri = extra_uri
		self.extra_component = extra_component
		self.extra_array_int = extra_array_int
		self.extra_array_long = extra_array_long
		self.extra_array_float = extra_array_float
		self.flags = flags
		self.suffix = suffix
		self.cmd = None
		self.get_cmd()

	def get_cmd(self):
		"""
		convert this intent to cmd string
		:rtype : object
		:return: str, cmd string
		"""
		if self.cmd is not None:
			return self.cmd
		cmd = "/system/bin/sh /system/bin/am "
		if self.prefix:
			cmd += self.prefix
		if self.action is not None:
			cmd += " -a " + self.action
		if self.data_uri is not None:
			cmd += " -d " + self.data_uri
		if self.mime_type is not None:
			cmd += " -t " + self.mime_type
		if self.category is not None:
			cmd += " -c " + self.category
		if self.component is not None:
			cmd += " -n " + self.component
		if self.flag is not None:
			cmd += " -f " + self.flag
		if self.extra_keys:
			for key in self.extra_keys:
				cmd += " --esn '%s'" % key
		if self.extra_string:
			for key in self.extra_string.keys():
				cmd += " -e '%s' '%s'" % (key, self.extra_string[key])
		if self.extra_boolean:
			for key in self.extra_boolean.keys():
				cmd += " -ez '%s' %s" % (key, self.extra_boolean[key])
		if self.extra_int:
			for key in self.extra_int.keys():
				cmd += " -ei '%s' %s" % (key, self.extra_int[key])
		if self.extra_long:
			for key in self.extra_long.keys():
				cmd += " -el '%s' %s" % (key, self.extra_long[key])
		if self.extra_float:
			for key in self.extra_float.keys():
				cmd += " -ef '%s' %s" % (key, self.extra_float[key])
		if self.extra_uri:
			for key in self.extra_uri.keys():
				cmd += " -eu '%s' '%s'" % (key, self.extra_uri[key])
		if self.extra_component:
			for key in self.extra_component.keys():
				cmd += " -ecn '%s' %s" % (key, self.extra_component[key])
		if self.extra_array_int:
			for key in self.extra_array_int.keys():
				cmd += " -eia '%s' %s" % (key, ",".join(self.extra_array_int[key]))
		if self.extra_array_long:
			for key in self.extra_array_long.keys():
				cmd += " -ela '%s' %s" % (key, ",".join(self.extra_array_long[key]))
		if self.extra_array_float:
			for key in self.extra_array_float.keys():
				cmd += " -efa '%s' %s" % (key, ",".join(self.extra_array_float[key]))
		if self.flags:
			cmd += " " + " ".join(self.flags)
		if self.suffix:
			cmd += " " + self.suffix
		self.cmd = cmd
		return self.cmd
