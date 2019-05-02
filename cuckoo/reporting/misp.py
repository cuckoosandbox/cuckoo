# Copyright (C) 2016-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import shlex
import warnings
import logging

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

class MISP(Report):
    """Enrich MISP with Cuckoo results."""

    def sample_hashes(self, results, event):
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

    def all_urls(self, results, event):
        """All of the accessed URLS as per the PCAP."""
        urls = set()
        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                urls.add("%s://%s%s" % (
                    entry["protocol"], entry["host"], entry["uri"]
                ))

        self.misp.add_url(event, sorted(list(urls)))

    def domain_ipaddr(self, results, event):
        whitelist = [
            "www.msftncsi.com", "dns.msftncsi.com", "teredo.ipv6.microsoft.com", "time.windows.com",
            "www.msftconnecttest.com", "v10.vortex-win.data.microsoft.com","settings-win.data.microsoft.com", 
            "win10.ipv6.microsoft.com", "sls.update.microsoft.com", "13.74.179.117", "40.81.120.221",
            "40.77.226.249", "8.8.8.8", "fs.microsoft.com", "ctldl.windowsupdate.com"
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

    def family(self, results, event):
        for config in results.get("metadata", {}).get("cfgextr", []):
            self.misp.add_detection_name(
                event, config["family"], "Sandbox detection"
            )
            for cnc in config.get("cnc", []):
                self.misp.add_url(event, cnc)
            for url in config.get("url", []):
                self.misp.add_url(event, cnc)
            for mutex in config.get("mutex", []):
                self.misp.add_mutex(event, mutex)
            for user_agent in config.get("user_agent", []):
                self.misp.add_useragent(event, user_agent)

    def signature(self, results, event):
        for sig in results["signatures"]:
            data = "%s - (%s)" % (sig["description"], ",".join(sig["ttp"]))
            self.misp.add_internal_comment(event, data)
            for att, description in sig["ttp"].items():
                if description is None:
                    log.warning("Description for %s is not found" % (att))
                    continue

                self.misp.add_internal_comment(event, "TTP: %s, short: %s" % (att, description["short"]))

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

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import pymisp

        self.misp = pymisp.PyMISP(url, apikey, False, "json")

        event = self.misp.new_event(
            distribution=pymisp.Distribution.all_communities.value,
            threat_level_id=pymisp.ThreatLevel.undefined.value,
            analysis=pymisp.Analysis.completed.value,
            info="Cuckoo Sandbox analysis #%d" % self.task["id"],
        )

        if results.get("target", {}).get("category") == "file":
            self.misp.upload_sample(
                filename=os.path.basename(self.task["target"]),
                filepath_or_bytes=self.task["target"],
                event_id=event["Event"]["id"],
                category="External analysis",
            )

        self.signature(results, event)

        if "hashes" in mode:
            self.sample_hashes(results, event)

        if "url" in mode:
            self.all_urls(results, event)

        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)

        self.family(results, event)
