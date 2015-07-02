# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import pickle
import socket
import logging
import xmlrpclib
from StringIO import StringIO
from zipfile import ZipFile, ZIP_STORED

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_GUEST_INIT
from lib.cuckoo.common.constants import CUCKOO_GUEST_COMPLETED
from lib.cuckoo.common.constants import CUCKOO_GUEST_FAILED
from lib.cuckoo.common.exceptions import CuckooGuestError
from lib.cuckoo.common.utils import TimeoutServer, sanitize_filename
from lib.cuckoo.core.resultserver import ResultServer

log = logging.getLogger(__name__)

class GuestManager:
    """Guest Manager.

    This class handles the communications with the agents running in the
    machines.
    """

    def __init__(self, vm_id, ip, platform="windows"):
        """@param ip: guest's IP address.
        @param platform: guest's operating system type.
        """
        self.id = vm_id
        self.ip = ip
        self.platform = platform

        self.cfg = Config()
        self.timeout = self.cfg.timeouts.critical

        url = "http://{0}:{1}".format(ip, CUCKOO_GUEST_PORT)
        self.server = TimeoutServer(url, allow_none=True,
                                    timeout=self.timeout)

    def wait(self, status):
        """Waiting for status.
        @param status: status.
        @return: always True.
        """
        log.debug("%s: waiting for status 0x%.04x", self.id, status)

        end = time.time() + self.timeout
        self.server._set_timeout(self.timeout)

        while True:
            # Check if we've passed the timeout.
            if time.time() > end:
                raise CuckooGuestError("{0}: the guest initialization hit the "
                                       "critical timeout, analysis "
                                       "aborted.".format(self.id))

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

    def upload_analyzer(self):
        """Upload analyzer to guest.
        @return: operation status.
        """
        zip_data = StringIO()
        zip_file = ZipFile(zip_data, "w", ZIP_STORED)

        # Select the proper analyzer's folder according to the operating
        # system associated with the current machine.
        root = os.path.join(CUCKOO_ROOT, "analyzer", self.platform)
        root_len = len(os.path.abspath(root))

        if not os.path.exists(root):
            log.error("No valid analyzer found at path: %s", root)
            return False

        # Walk through everything inside the analyzer's folder and write
        # them to the zip archive.
        for root, dirs, files in os.walk(root):
            archive_root = os.path.abspath(root)[root_len:]
            for name in files:
                path = os.path.join(root, name)
                archive_name = os.path.join(archive_root, name)
                zip_file.write(path, archive_name)

        zip_file.close()
        data = xmlrpclib.Binary(zip_data.getvalue())
        zip_data.close()

        log.debug("Uploading analyzer to guest (id=%s, ip=%s)",
                  self.id, self.ip)

        # Send the zip containing the analyzer to the agent running inside
        # the guest.
        try:
            self.server.add_analyzer(data)
        except socket.timeout:
            raise CuckooGuestError("{0}: guest communication timeout: unable "
                                   "to upload agent, check networking or try "
                                   "to increase timeout".format(self.id))

    def send_tool(self, tool_path, is_tool=False, base_dir="tool"):
        """Upload a file to the guest. 

        @param tool_path: path to tool/file on host
        @param is_tool: specifies whether file is the tool or a supporting file
        @param base_dir: path to place file on guest. path is appended to 
            guest temporary directory i.e. (%TEMP%).
        """
        if os.path.isfile(tool_path):
            if '/' in tool_path:
                index = tool_path.rfind("/")
                file_name = tool_path[index+1:]
                
            #The tool will have '.tool' appended to it in order to distinguish
            #it from any other 'exe' files in the same directory on the guest.
            if is_tool:
                file_name = file_name + ".tool"
            try:
                file_data = open(tool_path, 'rb').read()
            except (IOError, OSError) as e:
                raise CuckooGuestError("{0}: Unable to read tool file {1}: {2}".format(self.id, tool_path, e))

            data = xmlrpclib.Binary(file_data)

            try:
                self.server.add_malware(data, file_name, base_dir)
            except MemoryError as e:
                raise CuckooGuestError("{0}: unable to upload tool to analysis machine, not enough memory".format(self.id))
            return file_name

        else:
            raise CuckooGuestError("%s not a valid file/path(send_tool)." % tool_path)

    def send_dir(self, dir_path, base_dir):
        """Upload a directory and all it contains to the guest

        @param dir_path: path to directory on the host
        @param base_dir: path to place directory on guest. path is appended to 
            guest temporary directory i.e. (%TEMP%). 
        """
        uploaded_tools = []
        depth = 0
        for root, subdirs, files in os.walk(dir_path):
            if depth == 0:
                dest_dir = base_dir
                src_dir = src_root = root
            else:
                src_dir = root.replace(src_root, '', 1).lstrip('/')
                dest_dir = os.path.join(base_dir, src_dir)

            for item in files:
                self.send_tool(os.path.join(root, item), False, dest_dir)
                uploaded_tools.append(item)

            for subdir in subdirs:
                try:
                    self.server.add_malware('', '', os.path.join(dest_dir, subdir))
                    uploaded_tools.append(subdir)
                except MemoryError as e:
                    raise CuckooGuestError("{0}: unable to upload tool to analysis machine, not enough memory".format(self.id))

            depth = depth + 1
        return uploaded_tools

    def start_analysis(self, options):
        """Start analysis.
        @param options: options.
        @return: operation status.
        """
        log.info("Starting analysis on guest (id=%s, ip=%s)", self.id, self.ip)

        # TODO: deal with unicode URLs.
        if options["category"] == "file":
            options["file_name"] = sanitize_filename(options["file_name"])

        # If the analysis timeout is higher than the critical timeout,
        # automatically increase the critical timeout by one minute.
        if options["timeout"] > self.timeout:
            log.debug("Automatically increased critical timeout to %s",
                      self.timeout)
            self.timeout = options["timeout"] + 60

        # If tool is specified, you need to send certain options
        # upload_path, tool, uploaded_tools
        if options["tool"]:
            task_id = options["id"]
            upload_path = ',upload-path=' + os.path.join(CUCKOO_ROOT, "storage/analyses", str(task_id), "tool_output")
            options["options"] = options["options"] + upload_path

            index = options["tool"].rfind("/")
            tool_option = ",tool=" + options["tool"][index+1:]
            options["options"] = options["options"] + tool_option
            
            uploaded_tools = [options["tool"][index+1:].lower()]
            if options["tool_dir"]:
                for root, subdirs, files in os.walk(options["tool_dir"]):
                    uploaded_tools.extend(files)
                    uploaded_tools.extend(subdirs)
            options["options"] = options["options"] + ",uploaded_tools=" + pickle.dumps(uploaded_tools)

        # Get and set dynamically generated resultserver port.
        options["port"] = str(ResultServer().port)

        try:
            # Wait for the agent to respond. This is done to check the
            # availability of the agent and verify that it's ready to receive
            # data.
            self.wait(CUCKOO_GUEST_INIT)

            # Invoke the upload of the analyzer to the guest.
            self.upload_analyzer()

            # Give the analysis options to the guest, so it can generate the
            # analysis.conf inside the guest.
            try:
                self.server.add_config(options)
            except:
                raise CuckooGuestError("{0}: unable to upload config to "
                                       "analysis machine".format(self.id))

            # If a tool was specified, upload it to the guest.
            if options["tool"]:
                if options["tool"]:
                    self.send_tool(options["tool"], True)

                if options["tool_dir"]:
                    if not os.path.isdir(options["tool_dir"]):
                        raise CuckooGuestError("--tool-dir must be a directory")
                    self.send_dir(options["tool_dir"], 'tool')

            # If the target of the analysis is a file, upload it to the guest.
            if options["category"] == "file":
                try:
                    file_data = open(options["target"], "rb").read()
                except (IOError, OSError) as e:
                    raise CuckooGuestError("Unable to read {0}, error: "
                                           "{1}".format(options["target"], e))

                data = xmlrpclib.Binary(file_data)

                try:
                    self.server.add_malware(data, options["file_name"])
                except Exception as e:
                    raise CuckooGuestError("{0}: unable to upload malware to "
                                           "analysis machine: {1}".format(self.id, e))

            # Launch the analyzer.
            pid = self.server.execute()
            log.debug("%s: analyzer started with PID %d", self.id, pid)
        # If something goes wrong when establishing the connection, raise an
        # exception and abort the analysis.
        except (socket.timeout, socket.error):
            raise CuckooGuestError("{0}: guest communication timeout, check "
                                   "networking or try to increase "
                                   "timeout".format(self.id))

    def wait_for_completion(self):
        """Wait for analysis completion.
        @return: operation status.
        """
        log.debug("%s: waiting for completion", self.id)

        end = time.time() + self.timeout
        self.server._set_timeout(self.timeout)

        while True:
            time.sleep(1)

            # If the analysis hits the critical timeout, just return straight
            # away and try to recover the analysis results from the guest.
            if time.time() > end:
                raise CuckooGuestError("The analysis hit the critical timeout, terminating.")

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
                if not error:
                    error = "unknown error"

                raise CuckooGuestError("Analysis failed: {0}".format(error))
            else:
                log.debug("%s: analysis not completed yet (status=%s)",
                          self.id, status)

        self.server._set_timeout(None)
