# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os.path
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pymisp

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class MISP(Processing):
    """Enrich Cuckoo results with MISP data."""
    order = 3

    def search_ioc(self, ioc):
        try:
            r = self.misp.search_all(ioc)
        except Exception as e:
            log.debug("Error searching for IOC (%r) on MISP: %s", ioc, e)
            return

        if not r:
            return

        for row in r.get("response", []):
            event = row.get("Event", {})
            event_id = event.get("id")

            if event_id not in self.iocs:
                url = os.path.join(self.url, "events/view", "%s" % event_id)
                self.iocs[event_id] = {
                    "event_id": event_id,
                    "date": event.get("date"),
                    "url": url,
                    "level": event.get("threat_level_id"),
                    "info": event.get("info", "").strip(),
                    "iocs": [],
                }

            if ioc not in self.iocs[event_id]["iocs"]:
                self.iocs[event_id]["iocs"].append(ioc)

    def _parse_date(self, row):
        if not row.get("date"):
            return datetime.datetime.now()

        return datetime.datetime.strptime(row["date"], "%Y-%m-%d")

    def run(self):
        """Run analysis.
        @return: MISP results dict.
        """
        self.url = self.options.get("url", "")
        self.apikey = self.options.get("apikey", "")
        maxioc = int(self.options.get("maxioc", 100))

        if not self.url or not self.apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.key = "misp"
        self.iocs = {}

        self.misp = pymisp.PyMISP(self.url, self.apikey, False, "json")
        iocs = set()

        iocs.add(self.results.get("target", {}).get("file", {}).get("md5"))

        for dropped in self.results.get("dropped", []):
            iocs.add(dropped.get("md5"))

        iocs.update(self.results.get("network", {}).get("hosts", []))

        for block in self.results.get("network", {}).get("domains", []):
            iocs.add(block.get("ip"))
            iocs.add(block.get("domain"))

        # Remove empty entries and turn the collection into a list.
        iocs = list(iocs.difference((None, "")))

        # Acquire all information related to IOCs.
        for ioc in iocs[:maxioc]:
            self.search_ioc(ioc)

        # Sort IOC information by date and return all information.
        return sorted(
            self.iocs.values(), key=self._parse_date, reverse=True
        )
