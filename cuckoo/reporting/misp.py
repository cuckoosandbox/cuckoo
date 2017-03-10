# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import shlex
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import pymisp

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooProcessingError

class MISP(Report):
    """Enrich MISP with Cuckoo results."""

    def sample_hashes(self, results, event):
        """For now only reports hash of the analyzed file, not of the dropped
        files, as we may have hundreds or even thousands of dropped files, and
        the misp.add_hashes() method doesn't accept multiple arguments yet."""
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            self.misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to Cuckoo",
            )

    def maldoc_network(self, results, event):
        """Specific reporting functionality for malicious documents. Most of
        this functionality should be integrated more properly in the Cuckoo
        Core rather than being abused at this point."""
        urls = set()
        for signature in results.get("signatures", []):
            if signature["name"] != "malicious_document_urls":
                continue

            for mark in signature["marks"]:
                if mark["category"] == "url":
                    urls.add(mark["ioc"])

        self.misp.add_url(event, sorted(list(urls)))

    def all_urls(self, results, event):
        """All of the accessed URLS as per the PCAP. *Might* have duplicates
        when compared to the 'maldoc' mode, but e.g., in offline mode, when no
        outgoing traffic is allowed, 'maldoc' reports URLs that are not present
        in the PCAP (as the PCAP is basically empty)."""
        urls = set()
        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                urls.add("%s://%s%s" % (
                    entry["protocol"], entry["host"], entry["uri"]
                ))

        self.misp.add_url(event, sorted(list(urls)))

    def domain_ipaddr(self, results, event):
        whitelist = [
            "www.msftncsi.com", "dns.msftncsi.com",
            "teredo.ipv6.microsoft.com", "time.windows.com",
        ]

        domains, ips = {}, set()
        for domain in results.get("network", {}).get("domains", []):
            if domain["domain"] not in whitelist:
                domains[domain["domain"]] = domain["ip"]
                ips.add(domain["ip"])

        ipaddrs = set()
        for ipaddr in results.get("network", {}).get("hosts", []):
            if ipaddr not in ips:
                ipaddrs.add(ipaddr)

        self.misp.add_domains_ips(event, domains)
        self.misp.add_ipdst(event, sorted(list(ipaddrs)))

    def run(self, results):
        """Submits results to MISP.
        @param results: Cuckoo results dict.
        """
        url = self.options.get("url")
        apikey = self.options.get("apikey")
        mode = shlex.split(self.options.get("mode") or "")

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

        if results.get("target", {}).get("category") == "file":
            self.misp.upload_sample(
                filename=os.path.basename(self.task["target"]),
                filepath=self.task["target"],
                event_id=event["Event"]["id"],
                category="External analysis",
            )

        if "hashes" in mode:
            self.sample_hashes(results, event)

        if "maldoc" in mode:
            self.maldoc_network(results, event)

        if "url" in mode:
            self.all_urls(results, event)

        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)
