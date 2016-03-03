# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import subprocess

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class Moloch(Report):
    """Moloch reporting module."""

    def run(self, results):
        self.moloch_capture = \
            self.options.get("moloch_capture", "/data/moloch/bin/moloch-capture")
        self.config_path = self.options.get("conf", "/data/moloch/etc/config.ini")
        self.instance = self.options.get("instance", "cuckoo")

        if not os.path.isfile(self.pcap_path):
            log.warning("Unable to run Moloch as no pcap is available")
            return

        if not os.path.isfile(self.moloch_capture):
            raise CuckooProcessingError("Unable to locate Moloch binary")

        if not os.path.isfile(self.config_path):
            raise CuckooProcessingError(
                "Unable to locate Moloch configuration"
            )

        args = [
            self.moloch_capture,
            "-c", self.config_path,
            "-r", self.pcap_path,
            "-n", self.instance,
            "-q",
        ]

        tags = {}
        tags[self.instance] = self.task["id"]

        if self.task["category"] == "file":
            # Tag file hashes.
            f = results.get("target", {}).get("file", {})
            for field in ("md5", "sha1", "sha256", "sha512"):
                if field in f:
                    tags[field] = f[field]

            # Tag normalized VirusTotal results.
            for variant in results.get("virustotal", {}).get("normalized", []):
                tags["virustotal"] = variant

        for key, value in tags.items():
            args += [
                "-t", "%s:%s" % (key, value),
            ]

        try:
            subprocess.check_call(args)
        except subprocess.CalledProcessError as e:
            raise CuckooProcessingError(
                "Error submitting PCAP to Moloch: %s" % e)
