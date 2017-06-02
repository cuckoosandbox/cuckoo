# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import io
import json
import logging
import os
import requests
import socket
import time
import xmlrpclib
import zipfile

from cuckoo.common.config import config, parse_options
from cuckoo.common.constants import (
    CUCKOO_GUEST_PORT, CUCKOO_GUEST_INIT, CUCKOO_GUEST_COMPLETED,
    CUCKOO_GUEST_FAILED
)
from cuckoo.common.exceptions import (
    CuckooGuestError, CuckooGuestCriticalTimeout
)
from cuckoo.common.utils import TimeoutServer
from cuckoo.core.database import Database
from cuckoo.misc import cwd

log = logging.getLogger(__name__)
db = Database()

def analyzer_zipfile(platform, monitor):
    """Creates the Zip file that is sent to the Guest."""
    t = time.time()

    zip_data = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_data, "w", zipfile.ZIP_STORED)

    # Select the proper analyzer's folder according to the operating
    # system associated with the current machine.
    root = cwd("analyzer", platform)
    root_len = len(os.path.abspath(root))

    if not os.path.exists(root):
        log.error("No valid analyzer found at path: %s", root)
        raise CuckooGuestError(
            "No valid analyzer found for %s platform!" % platform
        )

    # Walk through everything inside the analyzer's folder and write
    # them to the zip archive.
    for root, dirs, files in os.walk(root):
        archive_root = os.path.abspath(root)[root_len:]
        for name in files:
            path = os.path.join(root, name)
            archive_name = os.path.join(archive_root, name)
            zip_file.write(path, archive_name)

    # Include the chosen monitoring component.
    if platform == "windows":
        dirpath = cwd("monitor", monitor)

        # Sometimes we might get a file instead of a symbolic link, in that
        # case we follow the semi-"symbolic link" manually.
        if os.path.isfile(dirpath):
            monitor = os.path.basename(open(dirpath, "rb").read().strip())
            dirpath = cwd("monitor", monitor)

        for name in os.listdir(dirpath):
            path = os.path.join(dirpath, name)
            archive_name = os.path.join("/bin", name)
            zip_file.write(path, archive_name)

    zip_file.close()
    data = zip_data.getvalue()

    if time.time() - t > 10:
        log.warning(
            "It took more than 10 seconds to build the Analyzer Zip for the "
            "Guest. This might be a serious performance penalty. Is your "
            "analyzer/windows/ directory bloated with unnecessary files?"
        )

    return data

class OldGuestManager(object):
    """Old and deprecated Guest Manager.

    This class handles the communications with the old agent running in the
    virtual machine.
    """

    def __init__(self, vm_id, ip, platform, task_id):
        """@param ip: guest's IP address.
        @param platform: guest's operating system type.
        """
        self.id = vm_id
        self.ip = ip
        self.platform = platform
        self.task_id = task_id

        # initialized in start_analysis so we can update the critical timeout
        # TODO, pull options parameter into __init__ so we can do this here
        self.timeout = None
        self.server = None

    def wait(self, status):
        """Waiting for status.
        @param status: status.
        @return: always True.
        """
        log.debug("%s: waiting for status 0x%.04x", self.id, status)

        end = time.time() + self.timeout
        self.server._set_timeout(self.timeout)

        while db.guest_get_status(self.task_id) == "starting":
            # Check if we've passed the timeout.
            if time.time() > end:
                raise CuckooGuestCriticalTimeout(
                    "Machine %s: the guest initialization hit the "
                    "critical timeout, analysis aborted." % self.id
                )

            try:
                # If the server returns the given status, break the loop
                # and return.
                if self.server.get_status() == status:
                    log.debug("%s: status ready", self.id)
                    break
            except:
                pass

            log.debug("%s: not ready yet", self.id)
            time.sleep(1)

        self.server._set_timeout(None)
        return True

    def upload_analyzer(self, monitor):
        """Upload analyzer to guest.
        @return: operation status.
        """
        zip_data = analyzer_zipfile(self.platform, monitor)

        log.debug(
            "Uploading analyzer to guest (id=%s, ip=%s, monitor=%s, size=%d)",
            self.id, self.ip, monitor, len(zip_data)
        )

        # Send the zip containing the analyzer to the agent running inside
        # the guest.
        try:
            self.server.add_analyzer(xmlrpclib.Binary(zip_data))
        except socket.timeout:
            raise CuckooGuestError("{0}: guest communication timeout: unable "
                                   "to upload agent, check networking or try "
                                   "to increase timeout".format(self.id))

    def start_analysis(self, options, monitor):
        """Start analysis.
        @param options: options.
        @return: operation status.
        """
        # TODO Deal with unicode URLs, should probably try URL encoding.
        # Unicode files are being taken care of.

        self.timeout = options["timeout"] + config("cuckoo:timeouts:critical")

        url = "http://{0}:{1}".format(self.ip, CUCKOO_GUEST_PORT)
        self.server = TimeoutServer(url, allow_none=True,
                                    timeout=self.timeout)

        try:
            # Wait for the agent to respond. This is done to check the
            # availability of the agent and verify that it's ready to receive
            # data.
            self.wait(CUCKOO_GUEST_INIT)

            # Invoke the upload of the analyzer to the guest.
            self.upload_analyzer(monitor)

            # Give the analysis options to the guest, so it can generate the
            # analysis.conf inside the guest.
            try:
                self.server.add_config(options)
            except:
                raise CuckooGuestError(
                    "%s: unable to upload config to analysis machine" %
                    self.id
                )

            # If the target of the analysis is a file, upload it to the guest.
            if options["category"] in ("file", "archive"):
                try:
                    file_data = open(options["target"], "rb").read()
                except (IOError, OSError) as e:
                    raise CuckooGuestError(
                        "Unable to read %s, error: %s" %
                        (options["target"], e)
                    )

                data = xmlrpclib.Binary(file_data)

                try:
                    self.server.add_malware(data, options["file_name"])
                except Exception as e:
                    raise CuckooGuestError(
                        "#%s: unable to upload malware to analysis "
                        "machine: %s" % (self.id, e)
                    )

            # Launch the analyzer.
            pid = self.server.execute()
            log.debug("%s: analyzer started with PID %d", self.id, pid)
        # If something goes wrong when establishing the connection, raise an
        # exception and abort the analysis.
        except (socket.timeout, socket.error):
            raise CuckooGuestError(
                "%s: guest communication timeout, check networking or try "
                "to increase timeout" % self.id
            )

    def wait_for_completion(self):
        """Wait for analysis completion.
        @return: operation status.
        """
        log.debug("%s: waiting for completion", self.id)

        end = time.time() + self.timeout
        self.server._set_timeout(self.timeout)

        while db.guest_get_status(self.task_id) == "running":
            time.sleep(1)

            # If the analysis hits the critical timeout, just return straight
            # away and try to recover the analysis results from the guest.
            if time.time() > end:
                log.info("%s: end of analysis reached!", self.id)
                return

            try:
                status = self.server.get_status()
            except Exception as e:
                log.debug("%s: error retrieving status: %s", self.id, e)
                continue

            # React according to the returned status.
            if status == CUCKOO_GUEST_COMPLETED:
                log.info("%s: analysis completed successfully", self.id)
                break
            elif status == CUCKOO_GUEST_FAILED:
                error = self.server.get_error()
                raise CuckooGuestError(
                    "Analysis failed: %s" % (error or "unknown error")
                )
            else:
                log.debug("%s: analysis not completed yet (status=%s)",
                          self.id, status)

        self.server._set_timeout(None)

class GuestManager(object):
    """This class represents the new Guest Manager. It operates on the new
    Cuckoo Agent which features a more abstract but more feature-rich API."""

    def __init__(self, vmid, ipaddr, platform, task_id, analysis_manager):
        self.vmid = vmid
        self.ipaddr = ipaddr
        self.port = CUCKOO_GUEST_PORT
        self.platform = platform
        self.task_id = task_id
        self.analysis_manager = analysis_manager
        self.timeout = None

        # Just in case we have an old agent inside the Virtual Machine. This
        # allows us to remain backwards compatible (for now).
        self.old = OldGuestManager(vmid, ipaddr, platform, task_id)
        self.is_old = False

        # We maintain the path of the Cuckoo Analyzer on the host.
        self.analyzer_path = None
        self.environ = {}

        self.options = {}

    @property
    def aux(self):
        return self.analysis_manager.aux

    def get(self, method, *args, **kwargs):
        """Simple wrapper around requests.get()."""
        do_raise = kwargs.pop("do_raise", True)
        url = "http://%s:%s%s" % (self.ipaddr, self.port, method)
        session = requests.Session()
        session.trust_env = False
        session.proxies = None
        r = session.get(url, *args, **kwargs)
        do_raise and r.raise_for_status()
        return r

    def post(self, method, *args, **kwargs):
        """Simple wrapper around requests.post()."""
        url = "http://%s:%s%s" % (self.ipaddr, self.port, method)
        session = requests.Session()
        session.trust_env = False
        session.proxies = None
        r = session.post(url, *args, **kwargs)
        r.raise_for_status()
        return r

    def wait_available(self):
        """Wait until the Virtual Machine is available for usage."""
        end = time.time() + self.timeout

        while db.guest_get_status(self.task_id) == "starting":
            try:
                socket.create_connection((self.ipaddr, self.port), 1).close()
                break
            except socket.timeout:
                log.debug("%s: not ready yet", self.vmid)
            except socket.error:
                log.debug("%s: not ready yet", self.vmid)
                time.sleep(1)

            if time.time() > end:
                raise CuckooGuestCriticalTimeout(
                    "Machine %s: the guest initialization hit the critical "
                    "timeout, analysis aborted." % self.vmid
                )

    def query_environ(self):
        """Query the environment of the Agent in the Virtual Machine."""
        self.environ = self.get("/environ").json()["environ"]

    def determine_analyzer_path(self):
        """Determine the path of the analyzer. Basically creating a temporary
        directory in the systemdrive, i.e., C:\\."""
        systemdrive = "%s\\" % self.environ["SYSTEMDRIVE"]

        options = parse_options(self.options["options"])
        if options.get("analpath"):
            dirpath = "%s\\%s" % (systemdrive, options["analpath"])
            r = self.post("/mkdir", data={"dirpath": dirpath})
            self.analyzer_path = dirpath
        else:
            r = self.post("/mkdtemp", data={"dirpath": systemdrive})
            self.analyzer_path = r.json()["dirpath"]

    def upload_analyzer(self, monitor):
        """Upload the analyzer to the Virtual Machine."""
        zip_data = analyzer_zipfile(self.platform, monitor)

        log.debug(
            "Uploading analyzer to guest (id=%s, ip=%s, monitor=%s, size=%d)",
            self.vmid, self.ipaddr, monitor, len(zip_data)
        )

        self.determine_analyzer_path()
        data = {
            "dirpath": self.analyzer_path,
        }
        self.post("/extract", files={"zipfile": zip_data}, data=data)

    def add_config(self, options):
        """Upload the analysis.conf for this task to the Virtual Machine."""
        config = [
            "[analysis]",
        ]
        for key, value in options.items():
            # Encode datetime objects the way xmlrpc encodes them.
            if isinstance(value, datetime.datetime):
                config.append("%s = %s" % (key, value.strftime("%Y%m%dT%H:%M:%S")))
            else:
                config.append("%s = %s" % (key, value))

        data = {
            "filepath": os.path.join(self.analyzer_path, "analysis.conf"),
        }
        self.post("/store", files={"file": "\n".join(config)}, data=data)

    def start_analysis(self, options, monitor):
        """Start the analysis by uploading all required files.

        @param options: the task options
        @param monitor: identifier of the monitor to be used.
        """
        log.info("Starting analysis on guest (id=%s, ip=%s)",
                 self.vmid, self.ipaddr)

        self.options = options
        self.timeout = options["timeout"] + config("cuckoo:timeouts:critical")

        # Wait for the agent to come alive.
        self.wait_available()

        # Could be beautified a bit, but basically we have to perform the
        # same check here as we did in wait_available().
        if db.guest_get_status(self.task_id) != "starting":
            return

        # Check whether this is the new Agent or the old one (by looking at
        # the status code of the index page).
        r = self.get("/", do_raise=False)
        if r.status_code == 501:
            # log.info("Cuckoo 2.0 features a new Agent which is more "
            #          "feature-rich. It is recommended to make new Virtual "
            #          "Machines with the new Agent, but for now falling back "
            #          "to backwards compatibility with the old agent.")
            self.is_old = True
            self.aux.callback("legacy_agent")
            self.old.start_analysis(options, monitor)
            return

        if r.status_code != 200:
            log.critical(
                "While trying to determine the Agent version that your VM is "
                "running we retrieved an unexpected HTTP status code: %s. If "
                "this is a false positive, please report this issue to the "
                "Cuckoo Developers. HTTP response headers: %s",
                r.status_code, json.dumps(dict(r.headers)),
            )
            db.guest_set_status(self.task_id, "failed")
            return

        try:
            status = r.json()
            version = status.get("version")
            features = status.get("features", [])
        except:
            log.critical(
                "We were unable to detect either the Old or New Agent in the "
                "Guest VM, are you sure you have set it up correctly? Please "
                "go through the documentation once more and otherwise inform "
                "the Cuckoo Developers of your issue."
            )
            db.guest_set_status(self.task_id, "failed")
            return

        log.info("Guest is running Cuckoo Agent %s (id=%s, ip=%s)",
                 version, self.vmid, self.ipaddr)

        # Pin the Agent to our IP address so that it is not accessible by
        # other Virtual Machines etc.
        if "pinning" in features:
            self.get("/pinning")

        # Obtain the environment variables.
        self.query_environ()

        # Upload the analyzer.
        self.upload_analyzer(monitor)

        # Pass along the analysis.conf file.
        self.add_config(options)

        # Allow Auxiliary modules to prepare the Guest.
        self.aux.callback("prepare_guest")

        # If the target is a file, upload it to the guest.
        if options["category"] == "file" or options["category"] == "archive":
            data = {
                "filepath": os.path.join(
                    self.environ["TEMP"], options["file_name"]
                ),
            }
            files = {
                "file": ("sample.bin", open(options["target"], "rb")),
            }
            self.post("/store", files=files, data=data)

        if "execpy" in features:
            data = {
                "filepath": "%s\\analyzer.py" % self.analyzer_path,
                "async": "yes",
                "cwd": self.analyzer_path,
            }
            self.post("/execpy", data=data)
        else:
            # Execute the analyzer that we just uploaded.
            data = {
                "command": "C:\\Python27\\pythonw.exe %s\\analyzer.py" % self.analyzer_path,
                "async": "yes",
                "cwd": self.analyzer_path,
            }
            self.post("/execute", data=data)

    def wait_for_completion(self):
        if self.is_old:
            self.old.wait_for_completion()
            return

        end = time.time() + self.timeout

        while db.guest_get_status(self.task_id) == "running":
            log.debug("%s: analysis still processing", self.vmid)

            time.sleep(1)

            # If the analysis hits the critical timeout, just return straight
            # away and try to recover the analysis results from the guest.
            if time.time() > end:
                log.info("%s: end of analysis reached!", self.vmid)
                return

            try:
                status = self.get("/status", timeout=5).json()
            except Exception as e:
                log.info("Virtual Machine /status failed (%r)", e)
                # this might fail due to timeouts or just temporary network issues
                # thus we don't want to abort the analysis just yet and wait for things to
                # recover
                continue

            if status["status"] == "complete":
                log.info("%s: analysis completed successfully", self.vmid)
                return
            elif status["status"] == "exception":
                log.warning(
                    "%s: analysis caught an exception\n%s",
                    self.vmid, status["description"]
                )
                return

    @property
    def server(self):
        """Currently the Physical machine manager is using GuestManager in
        an incorrect way. This should be fixed up later but for now this
        workaround will do."""
        return self.old.server
