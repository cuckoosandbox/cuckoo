# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooDependencyError

try:
    from pymisp import PyMISP
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

log = logging.getLogger(__name__)

class MISP(Processing):
    """Enrich Cuckoo results with MISP data."""

    def search_ioc(self, ioc):
        r = self.misp.search_all(ioc)
        if not r:
            return

        for row in r.get("response", []):
            event = row.get("Event", {})
            event_id = event.get("id")

            if event_id not in self.results:
                self.results[event_id] = {
                    "event_id": event_id,
                    "date": event.get("date"),
                    "url": self.url + "events/view/",
                    "level": event.get("threat_level_id"),
                    "info": event.get("info", "").strip(),
                    "iocs": [],
                }

            if ioc not in self.results[event_id]["iocs"]:
                self.results[event_id]["iocs"].append(ioc)

    def _parse_date(self, row):
        if not row.get("date"):
            return

        return datetime.datetime.strptime(row["date"], "%Y-%m-%d")

    def run(self):
        """Run analysis.
        @return: MISP results dict.
        """

        if not HAVE_MISP:
            raise CuckooDependencyError(
                "Unable to import PyMISP (install with `pip install pymisp`)"
            )

        self.url = self.options.get("url", "")
        self.apikey = self.options.get("apikey", "")

        if not self.url or not self.apikey:
            raise CuckooDependencyError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.key = "misp"
        self.results = {}

        self.misp = PyMISP(self.url, self.apikey, False, "json")
        iocs = set()

        iocs.add(self.results.get("target", {}).get("file", {}).get("md5"))

        for dropped in self.results.get("dropped", []):
            iocs.add(dropped.get("md5"))

        for block in self.results.get("network", {}).get("hosts", []):
            iocs.add(block.get("ip"))
            iocs.add(block.get("hostname"))

        # Remove empty entry.
        if None in iocs:
            iocs.remove(None)

        # Acquire all information related to IOCs.
        for ioc in iocs:
            self.search_ioc(ioc)

        # Sort IOC information by date and return all information.
        return sorted(
            self.results.values(), key=self._parse_date, reverse=True
        )
