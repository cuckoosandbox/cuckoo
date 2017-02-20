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
            "verified": False,
            "output": None
        }

        # Check to see if signtool is available...
        if os.path.isfile(self.signtool_path):
            self.enabled = True
        else:
            self.enabled = False

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

            nf = NetlogFile()
            nf.init("aux/signtool.json")
            nf.send(json.dumps(self.json_data))
            nf.close()

        except:
            import traceback
            log.exception(traceback.format_exc())

        return True
