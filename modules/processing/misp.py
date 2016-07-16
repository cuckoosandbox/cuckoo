# Copyright (C) 2010-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os.path
import threading
from collections import deque

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    from pymisp import PyMISP
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

log = logging.getLogger(__name__)

class MISP(Processing):
    """Enrich Cuckoo results with MISP data and upload iocs to MISP."""
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

    def cuckoo2misp_thread(self, iocs, event):

        while iocs:

            ioc = iocs.pop()
            if ioc.get("md5"):
                self.misp.add_hashes(event,
                                 md5=ioc["md5"],
                                 sha1=ioc["sha1"],
                                 sha256=ioc["sha256"]
                )
            elif ioc.get("domain", ""):
                self.misp.add_domain(event, ioc["domain"])
            elif ioc.get("ip", ""):
                self.misp.add_ipdst(event, ioc["ip"])
            elif ioc.get("uri", ""):
                self.misp.add_url(event, ioc["uri"])
            elif ioc.get("ua", ""):
                self.misp.add_useragent(event, ioc["ua"])
            elif ioc.get("mutex", ""):
                self.misp.add_mutex(event, ioc["mutex"])
            elif ioc.get("regkey", ""):
                self.misp.add_regkey(event, ioc["regkey"])


    def cuckoo2misp(self, results, whitelist):

        distribution = int(self.options.get("distribution", 0))
        threat_level_id = int(self.options.get("threat_level_id", 2))
        analysis = int(self.options.get("analysis", 2))

        iocs = deque()
        filtered_iocs = deque()
        threads_list = list()

        comment = "{} {}".format(self.options.get("title", ""), results.get('info', {}).get('id'))
        
        if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:                      
            iocs.append({"uri": results["target"]["url"]})
            filtered_iocs.append(results["target"]["url"])

        if self.options.get("network", False) and "network" in results.keys():
            for ip in results["network"].get("hosts", []):
                if ip not in whitelist and ip not in filtered_iocs:
                    iocs.append({"ip": ip})
                    filtered_iocs.append(ip)

            for block in results["network"].get("domains", []):
                if block.get("domain", "") and (block["domain"] not in whitelist and block["domain"] not in filtered_iocs):
                    iocs.append({"domain": block["domain"]})
                    filtered_iocs.append(block["domain"])

            for req in results["network"].get("http", []):
                if "user-agent" in req and req["user-agent"] not in filtered_iocs:
                    iocs.append({"ua": req["user-agent"]})
                    filtered_iocs.append(req["user-agent"])
                if "uri" in req and (req["uri"] not in whitelist and req["uri"] not in filtered_iocs):
                    iocs.append({"uri": req["uri"]})
                    filtered_iocs.append(req["uri"])

        if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
            if "mutexes" in results.get("behavior", {}).get("summary", {}):
                for mutex in results["behavior"]["summary"]["mutexes"]:
                    if mutex not in whitelist and mutex not in filtered_iocs:
                        iocs.append({"mutex": mutex})
                        filtered_iocs.append(mutex)

        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and (entry["md5"] not in filtered_iocs and entry["md5"] not in whitelist):
                    filtered_iocs.append(entry["md5"])
                    iocs.append({"md5": entry["md5"],
                                "sha1": entry["sha1"],
                                "sha256": entry["sha256"]
                    })
                    

        if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
            if "read_keys" in results["behavior"].get("summary", {}):
                for regkey in results["behavior"]["summary"]["read_keys"]:
                    if regkey not in whitelist and regkey not in filtered_iocs:
                        iocs.append({"regkey": regkey})
                        filtered_iocs.append(regkey)

        if iocs:
          
            event = self.misp.new_event(distribution, threat_level_id, analysis, comment, date=datatime.datetime.now().strftime('%Y-%m-%d'), published=True)

            if results.get("target", {}).get("file", ""):
                # Add Payload delivery hash about the details of the analyzed file
                self.misp.add_hashes(event, category='Payload delivery',
                                            filename=results.get('target').get('file').get('name'),
                                            md5=results.get('target').get('file').get('md5'),
                                            sha1=results.get('target').get('file').get('sha1'),
                                            sha256=results.get('target').get('file').get('sha256'),
                                            ssdeep=results.get('target').get('file').get('ssdeep'),
                                            comment='File: {} uploaded to cuckoo'.format(results.get('target').get('file').get('name')))
          
            for thread_id in xrange(int(self.threads)):
                thread = threading.Thread(target=self.cuckoo2misp_thread, args=(iocs, event))
                thread.daemon = True
                thread.start()

                threads_list.append(thread)

            for thread in threads_list:
                thread.join()

    def run(self):
        """Run analysis.
        @return: MISP results dict.
        """

        if not HAVE_MISP:
            raise CuckooDependencyError(
                "Unable to import PyMISP (install with `pip install pymisp`)"
            )

        whitelist = list()
        self.url = self.options.get("url", "")
        self.apikey = self.options.get("apikey", "")
        self.extend_context = self.options.get("extend_context", False)
        self.upload_iocs = self.options.get("upload_iocs", False)
        maxioc = int(self.options.get("maxioc", 100))
        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        # load whitelist if exists
        if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
            whitelist = Config("misp").whitelist.whitelist
            if whitelist:
                whitelist = [ioc.strip() for ioc in whitelist.split(",")]

        if not self.url or not self.apikey:
            raise CuckooProcessingError(
                "Please configure the URL and API key for your MISP instance."
            )

        # Ensure the URL ends with a trailing slash.
        if not self.url.endswith("/"):
            self.url += "/"

        self.key = "misp"
        self.iocs = {}

        self.misp = PyMISP(self.url, self.apikey, False, "json")
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

        if self.extend_context:
            # Acquire all information related to IOCs.
            for ioc in iocs[:maxioc]:
                self.search_ioc(ioc)

        if self.upload_iocs:
            self.cuckoo2misp(self.results, whitelist)

        # Sort IOC information by date and return all information.
        if self.iocs:
            return sorted(
                self.iocs.values(), key=self._parse_date, reverse=True
            )
