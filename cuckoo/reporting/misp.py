# Copyright (C) 2016-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import shlex
import warnings

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.whitelist import (
    is_whitelisted_mispdomain, is_whitelisted_mispip, is_whitelisted_mispurl,
    is_whitelisted_misphash
)

log = logging.getLogger(__name__)

class MISP(Report):
    """Enrich MISP with Cuckoo results."""

    def sample_hashes(self, results, event):
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            hash_ids = self.options.get("hash_ids") or False
            self.misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to Cuckoo",
                to_ids=hash_ids
            )

    def all_urls(self, results, event):
        """All of the accessed URLS as per the PCAP."""
        urls = set()
        for protocol in ("http_ex", "https_ex"):
            for entry in results.get("network", {}).get(protocol, []):
                if is_whitelisted_mispdomain(entry["host"]):
                    continue
                if is_whitelisted_mispdomain(entry["host"]):
                    continue

                url = "%s://%s%s" % (
                      entry["protocol"], entry["host"], entry["uri"])

                if not is_whitelisted_mispurl(url):
                    urls.add(url)
        url_ids = self.options.get("url_ids") or False
        self.misp.add_url(event, sorted(list(urls)), to_ids=url_ids)

    def domain_ipaddr(self, results, event):
        domains, ips = {}, set()
        for domain in results.get("network", {}).get("domains", []):
            if is_whitelisted_mispip(domain["ip"]):
                continue

            if is_whitelisted_mispdomain(domain["domain"]):
                continue

            domains[domain["domain"]] = domain["ip"]
            ips.add(domain["ip"])

        ipaddrs = set()
        for ipaddr in results.get("network", {}).get("hosts", []):
            if ipaddr not in ips and not is_whitelisted_mispip(ipaddr):
                ipaddrs.add(ipaddr)

        domain_ids = self.options.get("domain_ids") or False
        ip_ids = self.options.get("ip_ids") or False

        self.misp.add_domains_ips(event, domains, to_ids=domain_ids)
        self.misp.add_ipdst(event, sorted(list(ipaddrs)), to_ids=ip_ids)

    def family(self, results, event):
        url_ids = self.options.get("url_ids") or False
        mutex_ids = self.options.get("mutex_ids") or False
        useragent_ids = self.options.get("useragent_ids") or False

        for config in results.get("metadata", {}).get("cfgextr", []):
            self.misp.add_detection_name(
                event, config["family"], "External analysis"
            )
            for cnc in config.get("cnc", []):
                self.misp.add_url(event, cnc, to_ids=url_ids)
            for url in config.get("url", []):
                self.misp.add_url(event, url, to_ids=url_ids)
            for mutex in config.get("mutex", []):
                self.misp.add_mutex(event, mutex, to_ids=mutex_ids)
            for user_agent in config.get("user_agent", []):
                self.misp.add_useragent(event, user_agent, to_ids=useragent_ids)

    def signature(self, results, event):
        url_ids = self.options.get("url_ids") or False
        for sig in results.get("signatures", []):

            marks = []

            if sig["ttp"]:
                marks.append("%s" % ", ".join(sig["ttp"]))

            for mark in sig.get("marks", []):
                if mark["type"] == "generic":
                    marks.append(
                        "%s %s" % (mark.get("parent_process", ""),
                                   mark.get("martian_process", ""))
                    )
                    marks.append(
                        "%s %s" % (mark.get("reg_key", ""),
                                   mark.get("reg_value", ""))
                    )
                    marks.append(
                        "%s %s" % (mark.get("option", ""),
                                   mark.get("value", ""))
                    )
                    marks.append("%s" % mark.get("domain", ""))
                    marks.append("%s" % mark.get("description", ""))
                    marks.append("%s" % mark.get("host", ""))

                elif mark["type"] == "call":
                    if not mark["call"]["api"] in marks:
                        marks.append(mark["call"]["api"])
                elif mark["type"] == "config":
                    marks.append(mark["config"].get("url", ""))
                else:
                    marks.append(mark[mark["type"]])
                    if mark["category"] == "url":
                        url = mark.get("ioc", "")
                        if url.count('.') > 0:
                            self.misp.add_url(event, url, to_ids=url_ids)

            markslist = ", ".join([x for x in marks if x and x != " "])

            data = "%s - (%s)" % (sig["description"], markslist)
            self.misp.add_internal_comment(event, data)
            for att, description in sig["ttp"].items():
                if not description:
                    log.warning("Description for %s is not found", att)
                    continue

                self.misp.add_internal_comment(
                    event, "TTP: %s, short: %s" % (att, description["short"])
                )

    def run(self, results):
        """Submit results to MISP.
        @param results: Cuckoo results dict.
        """
        url = self.options.get("url")
        apikey = self.options.get("apikey")
        mode = shlex.split(self.options.get("mode") or "")
        score = results.get("info", {}).get("score", 0)
        upload_sample = self.options.get("upload_sample")

        if results.get("target", {}).get("category") == "file":
            f = results.get("target", {}).get("file", {})
            hash_whitelisted = is_whitelisted_misphash(f["md5"]) or \
                               is_whitelisted_misphash(f["sha1"]) or \
                               is_whitelisted_misphash(f["sha256"])

            if hash_whitelisted:
                return

        if score < self.options.get("min_malscore", 0):
            return

        if not url or not apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP "
                "instance."
            )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import pymisp

        self.misp = pymisp.PyMISP(url, apikey, False, "json")

        # Get default settings for a new event
        distribution = self.options.get("distribution") or 0
        threat_level = self.options.get("threat_level") or 4
        analysis = self.options.get("analysis") or 0
        tags = self.options.get("tag") or "Cuckoo"
        cuckoo_baseurl = self.options.get("cuckoo_baseurl")
        sample_ids = self.options.get("sample_ids") or False


        event = self.misp.new_event(
            distribution=distribution,
            threat_level_id=threat_level,
            analysis=analysis,
            info="Cuckoo Sandbox analysis #%d" % self.task["id"]
        )
        if cuckoo_baseurl:
            self.misp.add_internal_link(event, "{}/analysis/{}/summary/".format(cuckoo_baseurl, self.task["id"]),
                                        category='Internal reference')

        # Add a specific tag to flag Cuckoo's event
        for tag in tags.split(' '):
            mispresult = self.misp.tag(event["Event"]["uuid"], tag)
            if mispresult.has_key("message"):
                log.debug("tag event: %s" % mispresult["message"])

        if upload_sample:
            target = results.get("target", {})
            if target.get("category") == "file" and target.get("file"):
                self.misp.upload_sample(
                    filename=os.path.basename(self.task["target"]),
                    filepath_or_bytes=self.task["target"],
                    event_id=event["Event"]["id"],
                    category="External analysis",
                    to_ids=sample_ids
                )

        self.signature(results, event)

        if "hashes" in mode:
            self.sample_hashes(results, event)

        if "url" in mode:
            self.all_urls(results, event)

        if "ipaddr" in mode:
            self.domain_ipaddr(results, event)

        self.family(results, event)
