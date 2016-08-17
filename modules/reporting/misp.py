# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

import datetime
import logging
import os.path

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDependencyError

try:
    from pymisp import PyMISP
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

log = logging.getLogger(__name__)

class MISP(Report):
    """Enrich MISP results with CUCKOO iocs."""
    order = 3

    def send_to_misp(self, event, func, whitelist, data):
        iocs = list(set(data))

        for ioc in whitelist:
            if ioc in whitelist:
                data.remove(ioc)

        if data:
            # Upload 50 iocs in one request
            for block in data[::50]:
                try:
                    func(event, data[data.index(block)-50:data.index(block)])
                except Exception as e:
                    log.error(e)

    def run(self, results):
        """Run analysis.
        """

        if not HAVE_MISP:
            raise CuckooDependencyError(
                "Unable to import PyMISP (install with `pip install pymisp`)"
            )

        whitelist = list()
        uas = list()
        uris = list()
        self.url = self.options.get("url", "")
        self.apikey = self.options.get("apikey", "")
        maxioc = int(self.options.get("maxioc", 100))
        analysis = int(self.options.get("analysis", 2))
        distribution = int(self.options.get("distribution", 0))
        threat_level_id = int(self.options.get("threat_level_id", 2))
        comment = "{} {}".format(self.options.get("title", ""), results.get("info", {}).get("id"))

        # load whitelist if exists
        if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
            whitelist = Config("misp").whitelist.whitelist
            if whitelist:
                whitelist = [ioc.strip() for ioc in whitelist.split(",")]

        if not self.url or not self.apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )


        self.misp = PyMISP(self.url, self.apikey, False, "json")
        event = self.misp.new_event(distribution, 
                                        threat_level_id, 
                                        analysis, 
                                        comment, 
                                        date=datetime.datetime.now().strftime("%Y-%m-%d"), 
                                        published=True)

        misper = {
            "ips": self.misp.add_ipdst,
            "domains": self.misp.add_domain,
            "uas": self.misp.add_useragent,
            "uris": self.misp.add_url,
            "mutex": self.misp.add_mutex,
            "regkey": self.misp.add_regkey,
        }

        if results.get("target", {}).get("file", ""):
            # Add Payload delivery hash about the details of the analyzed file
            self.misp.add_hashes(event,
                      category="Payload delivery",
                      filename=results.get("target").get("file").get("name"),
                      md5=results.get("target").get("file").get("md5"),
                      sha1=results.get("target").get("file").get("sha1"),
                      sha256=results.get("target").get("file").get("sha256"),
                      ssdeep=results.get("target").get("file").get("ssdeep", ""),
                      comment="File: {} uploaded to cuckoo".format(results.get("target").get("file").get("name")))

        if self.options.get("dropped", False) and "dropped" in results:
            for dropped in results["dropped"][:maxioc]:
                self.misp.add_hashes(event,
                      filename=dropped["name"],
                      md5=dropped["md5"],
                      sha1=dropped["sha1"],
                      sha256=dropped["sha256"],
                      ssdeep=dropped.get("ssdeep", ""))

        if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:                      
            uri.append(results["target"]["url"])

        if self.options.get("network", False) and results.get("network", []).get("hosts", []):
            self.send_to_misp(event, misper["ips"], whitelist, results.get("network", []).get("hosts", []))
            domains = [part.get("domain") for part in results.get("network", []).get("domains", [])]
            self.send_to_misp(event, misper["domains"], whitelist, domains)
 
            for req in results["network"].get("http", []):
                if req.get("user-agent", "") and req.get("user-agent", "") not in whitelist:
                    uas.append(req["user-agent"])
                
                if req.get("uri", "") and req.get("uri", "") not in whitelist:
                    uris.append(req["uri"])
            
            self.send_to_misp(event, misper["uas"], whitelist, uas)
        
        self.send_to_misp(event, misper["uris"], whitelist, uris)    

        """ not support multiupload yet
        if results.get("behavior", {}).get("summary", {}):
            if self.options.get("registry", False):
                self.send_to_misp(event, misper["regkey"], whitelist, results["behavior"]["summary"].get("read_keys", []))
                self.send_to_misp(event, misper["regkey"], whitelist, results["behavior"]["summary"].get("regkey_opened", []))
                self.send_to_misp(event, misper["regkey"], whitelist, results["behavior"]["summary"].get("regkey_written", []))
            
            if self.options.get("mutexes", False):
                mutex = self.send_to_misp(event, misper["mutex"], whitelist, results["behavior"]["summary"].get("mutex", []))
        """
