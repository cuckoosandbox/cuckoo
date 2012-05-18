import os
import sys
import socket
import platform
import xmlrpclib
import subprocess
import ConfigParser
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_DEFLATED
import SocketServer
import ssl
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler
import os.path
import getopt

try:
    import fcntl
except ImportError:
    fcntl = None


BIND_IP = "0.0.0.0"
BIND_PORT = 8000

STATUS_INIT = 0x0001
STATUS_RUNNING = 0x0002
STATUS_COMPLETED = 0x0003
STATUS_FAILED = 0x0004

CURRENT_STATUS = STATUS_INIT

class AgentXMLRPCServer(SimpleXMLRPCServer):
    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=True, allow_none=False, encoding=None, bind_and_activate=True, useSSL=False, SSLCert=None):

        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)

        SocketServer.BaseServer.__init__(self, addr, requestHandler)
        if useSSL:
            self.socket = ssl.wrap_socket(
                socket.socket(self.address_family, self.socket_type),
                server_side=True,
                certfile=SSLCert,
                cert_reqs=ssl.CERT_NONE,
                ssl_version=ssl.PROTOCOL_SSLv23,
                )
        else:
            self.socket = socket.socket(self.address_family, self.socket_type)

        if bind_and_activate:
            self.server_bind()
            self.server_activate()

        # [Bug #1222790] If possible, set close-on-exec flag; if a
        # method spawns a subprocess, the subprocess shouldn't have
        # the listening socket open.
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)


class Agent:
    def __init__(self):
        self.error = ""
        self.system = platform.system().lower()
        self.analyzer_path = ""
        self.analyzer_pid = 0

    def _get_root(self, root="", container="cuckoo", create=True):
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
        return CURRENT_STATUS
   
    def get_error(self):
        if isinstance(self.error, Exception):
            if hasattr(self.error, "message"):
                return self.error.message
            else:
                return str(self.error)
        elif isinstance(self.error, str):
            return self.error

    def add_malware(self, data, name, iszip=False):
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
        global CURRENT_STATUS

        if success:
            CURRENT_STATUS = STATUS_COMPLETED
        else:
            if error:
                self.error = error

            CURRENT_STATUS = STATUS_FAILED

        return True

    def get_results(self):
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
        opts, args = getopt.getopt(sys.argv[1:], "s:p:",["ssl=,port="])
    except getopt.GetoptError:
        print "ERROR: usage: test.py [--ssl certfile.pem]"
        sys.exit(1)

    bind_port = BIND_PORT
    certfile = None
    for opt, arg in opts:
        if opt in ("-s", "--ssl"):
            if (os.path.exists(arg) and os.path.isfile(arg)):
                certfile = arg
            else:
                print("ERROR: certificate file '%s' does not exist" % arg)
                sys.exit(1)
        elif opt in ("-p", "--port"):
            bind_port = int(arg)

    try:
        if not BIND_IP:
            BIND_IP = socket.gethostbyname(socket.gethostname())

        print("[+] Starting agent on %s:%s ..." % (BIND_IP, bind_port))

        if certfile:
            server = AgentXMLRPCServer((BIND_IP, bind_port), allow_none=True, useSSL=True, SSLCert=certfile)
        else:
            server = AgentXMLRPCServer((BIND_IP, bind_port), allow_none=True)
     

        server.register_instance(Agent())
        server.serve_forever()

    except KeyboardInterrupt:
        server.shutdown()
