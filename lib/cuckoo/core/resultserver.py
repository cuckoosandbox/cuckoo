# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import socket
import logging
import SocketServer
from threading import Timer, Event, Thread

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.constants import *

log = logging.getLogger(__name__)

class Resultserver(SocketServer.ThreadingTCPServer):
    """Result server. Singleton!

    This class handles results coming back from the analysis VMs.
    """

	allow_reuse_address = True
	__instance= None

	def __new__(cls, *args, **kwargs):
		if cls != type(cls.__instance):
		  cls.__instance = object.__new__(cls, *args, **kwargs)
		return cls.__instance

    def __init__(self, *args, **kwargs):
    	SocketServer.ThreadingTCPServer.__init__(self, *args, **kwargs)
    	self.analysistasks = {}

    def add_task(self, task, machine):
    	self.analysistasks[machine.ip] = (task, machine)

    def del_task(self, task, machine):
    	del self.analysistasks[machine.ip]
    	