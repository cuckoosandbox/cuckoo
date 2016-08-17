# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import pymisp
import shlex

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooProcessingError

class MISP(Report):
    """Enrich MISP with Cuckoo results."""

    def maldoc_network(self, results, event):
        """Specific reporting functionality for malicious documents. Most of
        this functionality should be integrated more properly in the Cuckoo
        Core rather than being abused at this point."""
        urls = []
        for signature in results["signatures"]:
            if signature["name"] != "malicious_document_urls":
                continue

            for mark in signature["marks"]:
                if mark["category"] == "url":
                    urls.append(mark["ioc"])

        self.misp.add_url(event, urls)

    def domain_ipaddr(self, results, event):
        whitelist = [
            "www.msftncsi.com", "dns.msftncsi.com",
            "teredo.ipv6.microsoft.com", "time.windows.com",
        ]

        domains, ips = {}, set()
        for domain in results["network"].get("domains", []):
            if domain["domain"] not in whitelist:
                domains[domain["domain"]] = domain["ip"]
                ips.add(domain["ip"])

        ipaddrs = set()
        for ipaddr in results["network"].get("hosts", []):
            if ipaddr not in ips:
                ipaddrs.add(ipaddr)

        self.misp.add_domains_ips(event, domains)
        self.misp.add_ipdst(event, list(ipaddrs))

    def run(self, results):
        """Submits results to MISP.
        @param results: Cuckoo results dict.
        """
        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")
        mode = shlex.split(self.options.get("mode", ""))

        if not url or not apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        self.misp = pymisp.PyMISP(url, apikey, False, "json")

        event = self.misp.new_event(
            distribution=self.misp.distributions.all_communities,
            threat_level_id=self.misp.threat_level.undefined,
            analysis=self.misp.analysis.completed,
            info="Cuckoo Sandbox analysis #%d" % self.task["id"],
        )

        self.misp.upload_sample(
            filename=os.path.basename(self.task["target"]),
            filepath=self.task["target"],
            event_id=event["Event"]["id"],
            category="External analysis",
        )

        if "maldoc" in mode:
            self.maldoc_network(results, event)

        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)
