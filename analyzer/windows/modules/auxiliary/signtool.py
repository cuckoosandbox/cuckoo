# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import subprocess

from lib.common.abstracts import Auxiliary
from lib.api.process import subprocess_checkoutput
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)


class SignTool(Auxiliary):
    """
    This class contains the information about the signature verification
    for Microsoft Windows PE files.  This class requires signtool.exe in
    the analyzer/windows/bin directory so it will be copied to the guest VM.
    Signtool.exe is packaged with Windows SDKs and can be downloaded
    from Microsoft.
    """
    def __init__(self, options, analyzer):
        """
        Creates a SignTool object.

        :param options:  An options variable as required by Auxiliary.
        :param analyzer:  An analyzer object required by Auxiliary.
        """
        Auxiliary.__init__(self, options, analyzer)

        self.signtool_path = os.path.join(os.getcwd(), 'bin', 'signtool.exe')

        self.signature_chain = list()
        self.timestamp_chain = list()

        self.json_data = {
            "sha1": None,
            "signature_chain": list(),
            "timestamp": None,
            "timestamp_chain": list(),
            "verified": False,
            "output": None
        }

        # Check to see if signtool is available...
        if os.path.isfile(self.signtool_path):
            self.enabled = True
        else:
            self.enabled = False

    def _parse_chains(self):
        """
        This function parses the stored chains into a JSON object.

        :return: Nothing.
        """
        current_item = 0

        while current_item < len(self.signature_chain):
            current = dict()
            current["issued_to"] = \
                self.signature_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["issued_by"] = \
                self.signature_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["expires"] = \
                self.signature_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["sha1"] = \
                self.signature_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            self.json_data["signature_chain"].append(current)

        current_item = 0

        while current_item < len(self.timestamp_chain):
            current = dict()
            current["issued_to"] = \
                self.timestamp_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["issued_by"] = \
                self.timestamp_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["expires"] = \
                self.timestamp_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            current["sha1"] = \
                self.timestamp_chain[current_item].split(":", 1)[1].strip()
            current_item += 1
            self.json_data["timestamp_chain"].append(current)

    def _store_signature(self, datatype, line):
        """
        This function stores the data from signtool's output for later parsing.

        :param datatype:  The type of chain to store.
        :param line:  The line from the signtool output.
        :return:  Nothing.
        """
        if line and line.strip() != "":
            if datatype == "cert":
                self.signature_chain.append(line.strip())
            if datatype == "time":
                self.timestamp_chain.append(line.strip())

    def _parse_signtool(self, data):
        """
        This function parses the signtool output.

        :param data:  The output data to parse.
        :return:  Nothing.
        """
        current_parser = None

        for line in data.splitlines():
            if (line.startswith("Hash of file (sha1)") or
                    line.startswith("SHA1 hash of file")):
                if not self.json_data["sha1"]:
                    self.json_data["sha1"] = line.split(": ")[-1].lower()
            if line.startswith("Signing Certificate Chain:"):
                current_parser = "cert"
                continue
            if line.startswith("The signature is timestamped:"):
                current_parser = None
                if not self.json_data["timestamp"]:
                    self.json_data["timestamp"] = line.split(": ")[-1]
            if line.startswith("File is not timestamped."):
                current_parser = None
            if line.startswith("Timestamp Verified by:"):
                current_parser = "time"
                continue
            if line.startswith("File has page hashes"):
                current_parser = None
            if line.startswith("Number of files"):
                current_parser = None
            if line.startswith("Successfully verified"):
                current_parser = None
            if line.strip() == "":
                continue
            if current_parser == "cert":
                self._store_signature("cert", line)
            if current_parser == "time":
                self._store_signature("time", line)

        self._parse_chains()

    def start(self):
        """
        Starts the signtool.exe analysis and saves the results in
        aux/signtool.json.

        :return:  True if this function worked, False if it was unable to run.
            This is not the same as True or False if the
            Authenticode verification worked!
        """
        try:
            # Return False if this is not enabled.
            if not self.enabled:
                return False

            if self.analyzer.config.category != 'file':
                log.debug("Can only run signtool.exe on a file.")
                return False

            if not os.path.isfile(self.signtool_path):
                log.info("signtool.exe is not available at {0}, "
                         "skipping verification.".format(self.signtool_path))
                return False

            filepath = os.path.join(os.environ["TEMP"],
                                    self.analyzer.config.file_name)

            cmds = [self.signtool_path, "verify", "/pa", "/v", filepath]

            results = {}

            try:
                self.json_data["output"] = "".join(subprocess_checkoutput(cmds))
                self.json_data["verified"] = True
            except subprocess.CalledProcessError as e:
                self.json_data["verified"] = False
                self.json_data["output"] = "".join(e.output)

            self._parse_signtool(self.json_data["output"])

            nf = NetlogFile()
            nf.init("aux/signtool.json")
            nf.send(json.dumps(self.json_data))
            nf.close()

        except:
            import traceback
            log.exception(traceback.format_exc())

        return True
