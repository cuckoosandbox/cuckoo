# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import socket
import logging
import xmlrpclib
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_DEFLATED

from lib.cuckoo.common.exceptions import CuckooGuestError
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_GUEST_INIT, CUCKOO_GUEST_COMPLETED, CUCKOO_GUEST_FAILED

log = logging.getLogger(__name__)

class GuestManager:
    """Guest machine manager."""

    def __init__(self, vm_id, ip, platform="windows"):
        """@param ip: guest IP address.
        @param platform: OS type.
        """
        self.id = vm_id
        self.ip = ip
        self.platform = platform
        self.server = xmlrpclib.Server("http://%s:%s" % (ip, CUCKOO_GUEST_PORT), allow_none=True)

    def wait(self, status):
        """Waiting for status.
        @param status: status.
        @return: always True.
        """
        log.debug("%s: waiting for status 0x%.04x" % (self.id, status))

        while True:
            try:
                if self.server.get_status() == status:
                    log.debug("%s: status ready" % self.id)
                    break
            except:
                pass

            log.debug("%s: not ready yet" % self.id)
            time.sleep(1)

        return True

    def upload_analyzer(self):
        """Upload analyzer to guest.
        @return: operation status.
        """
        zip_data = StringIO()
        zip_file = ZipFile(zip_data, "w", ZIP_DEFLATED)

        root = os.path.join("analyzer", self.platform)
        root_len = len(os.path.abspath(root))

        if not os.path.exists(root):
            log.error("No valid analyzer found at path: %s" % root)
            return False

        for root, dirs, files in os.walk(root):
            archive_root = os.path.abspath(root)[root_len:]
            for name in files:
                path = os.path.join(root, name)
                archive_name = os.path.join(archive_root, name)
                zip_file.write(path, archive_name, ZIP_DEFLATED)

        zip_file.close()
        data = xmlrpclib.Binary(zip_data.getvalue())
        zip_data.close()

        log.debug("Uploading analyzer to guest (id=%s, ip=%s)" % (self.id, self.ip))
        self.server.add_analyzer(data)

    def start_analysis(self, options):
        """Start analysis.
        @param options: options.
        @return: operation status.
        """
        if not os.path.exists(options["file_path"]):
            return False

        log.info("Starting analysis on guest (id=%s, ip=%s)" % (self.id, self.ip))

        socket.setdefaulttimeout(180)

        try:
            self.wait(CUCKOO_GUEST_INIT)
            self.upload_analyzer()
            self.server.add_config(options)
    
            with open(options["file_path"], "rb") as malware_file:
                data = xmlrpclib.Binary(malware_file.read())
                self.server.add_malware(data, options["file_name"])
    
            self.server.add_malware(data, options["file_name"])
            self.server.execute()
        except socket.timeout:
            raise CuckooGuestError("%s: guest communication timeout, check networking or try to increase timeout" % self.id)

    def wait_for_completion(self):
        """Wait for analysis completion.
        @return: operation status.
        """
        while True:
            try:
                status = self.server.get_status()
                if status == CUCKOO_GUEST_COMPLETED:
                    log.info("%s: analysis completed successfully" % self.id)
                    break
                elif status == CUCKOO_GUEST_FAILED:
                    log.error("%s: analysis failed: %s" % (self.id, self.server.get_error()))
                    return False
                else:
                    log.debug("%s: analysis not completed yet" % self.id)
            except:
                pass

            time.sleep(1)
        
        return True

    def save_results(self, folder):
        """Save analysis results.
        @param folder: analysis folder path.
        @return: operation status.
        """
        data = self.server.get_results()

        zip_data = StringIO()
        zip_data.write(data)

        archive = ZipFile(zip_data, "r")
        if not os.path.exists(folder):
            try:
                os.mkdir(folder)
            except (IOError, OSError) as e:
                log.exception("Failed to create the results folder")
                return False

        log.debug("Extracting results to %s" % folder)
        archive.extractall(folder)
        archive.close()

        return True
