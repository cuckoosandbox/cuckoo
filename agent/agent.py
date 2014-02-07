# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import time
import socket
import string
import random
import platform
import subprocess
import ConfigParser
from StringIO import StringIO
from zipfile import ZipFile
from SimpleXMLRPCServer import SimpleXMLRPCServer

BIND_IP = "0.0.0.0"
BIND_PORT = 8000

STATUS_INIT = 0x0001
STATUS_RUNNING = 0x0002
STATUS_COMPLETED = 0x0003
STATUS_FAILED = 0x0004
CURRENT_STATUS = STATUS_INIT

ERROR_MESSAGE = ""
ANALYZER_FOLDER = ""
RESULTS_FOLDER = ""

class Agent:
    """Cuckoo agent, it runs inside guest."""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.analyzer_path = ""
        self.analyzer_pid = 0

    def _initialize(self):
        global ERROR_MESSAGE
        global ANALYZER_FOLDER

        if not ANALYZER_FOLDER:
            random.seed(time.time())
            container = "".join(random.choice(string.ascii_lowercase) for x in range(random.randint(5, 10)))

            if self.system == "windows":
                system_drive = os.environ["SYSTEMDRIVE"] + os.sep
                ANALYZER_FOLDER = os.path.join(system_drive, container)
            elif self.system == "linux" or self.system == "darwin":
                ANALYZER_FOLDER = os.path.join(os.environ["HOME"], container)
            else:
                ERROR_MESSAGE = "Unable to identify operating system"
                return False

            try:
                os.makedirs(ANALYZER_FOLDER)
            except OSError as e:
                ERROR_MESSAGE = e
                return False

        return True

    def get_status(self):
        """Get current status.
        @return: status.
        """
        return CURRENT_STATUS

    def get_error(self):
        """Get error message.
        @return: error message.
        """
        return str(ERROR_MESSAGE)

    def add_malware(self, data, name):
        """Get analysis data.
        @param data: analysis data.
        @param name: file name.
        @return: operation status.
        """
        global ERROR_MESSAGE
        data = data.data

        if self.system == "windows":
            root = os.environ["TEMP"]
        elif self.system == "linux" or self.system == "darwin":
            root = "/tmp"
        else:
            ERROR_MESSAGE = "Unable to write malware to disk because of " \
                            "failed identification of the operating system"
            return False

        file_path = os.path.join(root, name)

        try:
            with open(file_path, "wb") as malware:
                malware.write(data)
        except IOError as e:
            ERROR_MESSAGE = "Unable to write malware to disk: {0}".format(e)
            return False

        return True

    def add_config(self, options):
        """Creates analysis.conf file from current analysis options.
        @param options: current configuration options, dict format.
        @return: operation status.
        """
        global ERROR_MESSAGE

        if type(options) != dict:
            return False

        config = ConfigParser.RawConfigParser()
        config.add_section("analysis")

        try:
            for key, value in options.items():
                # Options can be UTF encoded.
                if isinstance(value, basestring):
                    try:
                        value = value.encode("utf-8")
                    except UnicodeEncodeError:
                        pass

                config.set("analysis", key, value)

            config_path = os.path.join(ANALYZER_FOLDER, "analysis.conf")
        
            with open(config_path, "wb") as config_file:
                config.write(config_file)
        except Exception as e:
            ERROR_MESSAGE = str(e)
            return False

        return True

    def add_analyzer(self, data):
        """Add analyzer.
        @param data: analyzer data.
        @return: operation status.
        """
        data = data.data

        if not self._initialize():
            return False

        try:
            zip_data = StringIO()
            zip_data.write(data)

            with ZipFile(zip_data, "r") as archive:
                archive.extractall(ANALYZER_FOLDER)
        finally:
            zip_data.close()

        self.analyzer_path = os.path.join(ANALYZER_FOLDER, "analyzer.py")

        return True

    def execute(self):
        """Execute analysis.
        @return: analyzer PID.
        """
        global ERROR_MESSAGE
        global CURRENT_STATUS

        if not self.analyzer_path or not os.path.exists(self.analyzer_path):
            return False

        try:
            proc = subprocess.Popen([sys.executable, self.analyzer_path],
                                    cwd=os.path.dirname(self.analyzer_path))
            self.analyzer_pid = proc.pid
        except OSError as e:
            ERROR_MESSAGE = str(e)
            return False

        CURRENT_STATUS = STATUS_RUNNING

        return self.analyzer_pid

    def complete(self, success=True, error="", results=""):
        """Complete analysis.
        @param success: success status.
        @param error: error status.
        """ 
        global ERROR_MESSAGE
        global CURRENT_STATUS
        global RESULTS_FOLDER

        if success:
            CURRENT_STATUS = STATUS_COMPLETED
        else:
            if error:
                ERROR_MESSAGE = str(error)

            CURRENT_STATUS = STATUS_FAILED

        RESULTS_FOLDER = results

        return True

if __name__ == "__main__":
    try:
        if not BIND_IP:
            BIND_IP = socket.gethostbyname(socket.gethostname())

        print("[+] Starting agent on %s:%s ..." % (BIND_IP, BIND_PORT))

        # Disable DNS lookup, by Scott D.
        def FakeGetFQDN(name=""):
            return name
        socket.getfqdn = FakeGetFQDN

        server = SimpleXMLRPCServer((BIND_IP, BIND_PORT), allow_none=True)
        server.register_instance(Agent())
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
