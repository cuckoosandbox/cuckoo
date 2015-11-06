# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os.path
import re
import subprocess

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class Snort(Processing):
    """Snort processing module."""

    # Thanks to Steve Handerson for the following regex query.
    alert_re = re.compile(
        r"(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
        r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
        r"(?P<message>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] ){0,1}"
        r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>[a-zA-Z0-9_-]+)\} "
        r"(?P<src>.+) \-\> (?P<dest>.+)"
    )

    def run(self):
        self.key = "snort"

        results = []

        self.snort = self.options.get("snort", "/usr/local/bin/snort")
        self.config_path = self.options.get("conf", "/etc/snort/snort.conf")

        if not os.path.isfile(self.pcap_path):
            log.warning("Unable to run Snort as no pcap is available")
            return self.results

        if not os.path.isfile(self.snort):
            raise CuckooProcessingError("Unable to locate Snort binary")

        if not os.path.isfile(self.config_path):
            raise CuckooProcessingError(
                "Unable to locate Snort configuration")

        args = [
            self.snort,
            "-c", self.config_path,
            "-A", "console",
            "-r", self.pcap_path,
            "-q", "-y",
        ]

        try:
            output = subprocess.check_output(args)
        except subprocess.CalledProcessError as e:
            raise CuckooProcessingError(
                "Snort returned an error processing this pcap: %s" % e)

        for line in output.split("\n"):
            if not line:
                continue

            x = self.alert_re.match(line)
            if not x:
                log.warning("Error matching Snort line: %r", line)
                continue

            timestamp = datetime.datetime.strptime(
                x.group("timestamp"), "%m/%d/%y-%H:%M:%S.%f")

            results.append({
                "timestamp": timestamp,
                "sid": int(x.group("sid")),
                "priority": int(x.group("priority")),
                "revision": int(x.group("revision")),
                "message": x.group("message"),
                "src_ip": x.group("src"),
                "dst_ip": x.group("dest"),
                "protocol": x.group("protocol"),
                "classtype": x.group("classtype"),
            })

        return results
