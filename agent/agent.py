# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import socket
import platform
import xmlrpclib
import subprocess
import ConfigParser
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_DEFLATED
from SimpleXMLRPCServer import SimpleXMLRPCServer

BIND_IP = "0.0.0.0"
BIND_PORT = 8000

STATUS_INIT = 0x0001
STATUS_RUNNING = 0x0002
STATUS_COMPLETED = 0x0003
STATUS_FAILED = 0x0004

CURRENT_STATUS = STATUS_INIT

class Agent:
    """Cuckoo agent, it runs inside guest."""
    
    def __init__(self):
        self.error = ""
        self.system = platform.system().lower()
        self.analyzer_path = ""
        self.analyzer_pid = 0

    def _get_root(self, root="", container="cuckoo", create=True):
        """Get Cuckoo path.
        @param root: root folder.
        @param container: folder which will contain Cuckoo.
        @param create: create folder.
        """
        if not root:
            if self.system == "windows":
                root = os.path.join(os.environ["SYSTEMDRIVE"] + os.sep, container)
            elif self.system == "linux" or self.system == "darwin":
                root = os.path.join(os.environ["HOME"], container)

        if create and not os.path.exists(root):
            try:
                os.makedirs(root)
            except OSError as e:
                self.error = e
                return False

        return root

    def get_status(self):
        """Get current status.
        @return: status.
        """
        return CURRENT_STATUS
   
    def get_error(self):
        """Get error message.
        @return: error message.
        """
        if isinstance(self.error, Exception):
            if hasattr(self.error, "message"):
                return self.error.message
            else:
                return str(self.error)
        elif isinstance(self.error, str):
            return self.error

    def add_malware(self, data, name, iszip=False):
        """Get analysis data.
        @param data: analysis data.
        @param name: file name.
        @param iszip: is a zip file.
        @return: operation status.
        """
        data = data.data
        root = self._get_root(container="")

        if not root:
            return False

        if iszip:
            try:
                zip_data = StringIO()
                zip_data.write(data)
            
                with ZipFile(zip_data, "r") as archive:
                    try:
                        archive.extractall(root)
                    except BadZipfile as e:
                        self.error = e
                        return False
                    except RuntimeError:
                        try:
                            archive.extractall(path=root, pwd="infected")
                        except RuntimeError as e:
                            self.error = e
                            return False
            finally:
                zip_data.close()
        else:
            file_path = os.path.join(root, name)

            with open(file_path, "wb") as malware:
                malware.write(data)

        return True

    def add_config(self, options):
        """Add configuration.
        @param options: configuration options.
        @return: operation status.
        """
        root = self._get_root()

        if not root:
            return False

        if type(options) != dict:
            return False

        config = ConfigParser.RawConfigParser()
        config.add_section("analysis")

        for key, value in options.items():
            config.set("analysis", key, value)

        config_path = os.path.join(root, "analysis.conf")
        with open(config_path, "wb") as config_file:
            config.write(config_file)

        return True

    def add_analyzer(self, data):
        """Add analyzer.
        @param data: analyzer data.
        @return: operation status.
        """
        data = data.data
        root = self._get_root(container="analyzer")

        if not root:
            return False

        try:
            zip_data = StringIO()
            zip_data.write(data)

            with ZipFile(zip_data, "r") as archive:
                archive.extractall(root)
        finally:
            zip_data.close()

        self.analyzer_path = os.path.join(root, "analyzer.py")

        return True

    def execute(self):
        """Execute analysis.
        @return: analyzer PID.
        """
        global CURRENT_STATUS

        if not self.analyzer_path or not os.path.exists(self.analyzer_path):
            return False

        try:
            proc = subprocess.Popen([sys.executable, self.analyzer_path], cwd=os.path.dirname(self.analyzer_path))
            self.analyzer_pid = proc.pid
        except OSError as e:
            self.error = e
            return False

        CURRENT_STATUS = STATUS_RUNNING

        return self.analyzer_pid

    def complete(self, success=True, error=None):
        """Complete analysis.
        @param success: success status.
        @param error: error status.
        """ 
        global CURRENT_STATUS

        if success:
            CURRENT_STATUS = STATUS_COMPLETED
        else:
            if error:
                self.error = error

            CURRENT_STATUS = STATUS_FAILED

        return True

    def get_results(self):
        """Get analysis results.
        @return: data.
        """
        root = self._get_root(container="cuckoo", create=False)

        if not os.path.exists(root):
            return False

        zip_data = StringIO()
        zip_file = ZipFile(zip_data, "w", ZIP_DEFLATED)

        root_len = len(os.path.abspath(root))
        
        for root, dirs, files in os.walk(root):
            archive_root = os.path.abspath(root)[root_len:]
            for name in files:
                path = os.path.join(root, name)
                archive_name = os.path.join(archive_root, name)
                zip_file.write(path, archive_name, ZIP_DEFLATED)
        
        zip_file.close()
        data = xmlrpclib.Binary(zip_data.getvalue())
        zip_data.close()

        return data

if __name__ == "__main__":
    try:
        if not BIND_IP:
            BIND_IP = socket.gethostbyname(socket.gethostname())

        print("[+] Starting agent on %s:%s ..." % (BIND_IP, BIND_PORT))

        server = SimpleXMLRPCServer((BIND_IP, BIND_PORT), allow_none=True)
        server.register_instance(Agent())
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
