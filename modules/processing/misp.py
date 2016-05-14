### MISP integration

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

import os
import logging
import threading
from collections import deque
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT

PYMISP = False
try:
    from pymisp import PyMISP
    PYMISP = True
except ImportError:
    pass

log = logging.getLogger(__name__)

class MISP(Processing):
    """MISP Analyzer."""

    order = 2

    def misper_thread(self, url):
        while self.iocs:
            ioc = self.iocs.pop()
            try:
                response = self.misp.search_all(ioc)
                if response and response.get("response", {}):
                    self.lock.acquire()
                    for res in response.get("response", {}):
                        event = res.get("Event", {})
                        eid = res.get("Event", {}).get("id", 0)
                        if eid in self.misper and ioc not in self.misper[eid]["iocs"]:
                            self.misper[eid]["iocs"].append(ioc)
                        else:
                            tmp_misp = dict()
                            tmp_misp.setdefault(eid, dict())
                            date = event.get("date", "")
                            if "iocs" not in tmp_misp[eid]:
                                tmp_misp[eid].setdefault("iocs", list())
                            tmp_misp[eid]["iocs"].append(ioc)
                            tmp_misp[eid].setdefault("eid", eid)
                            tmp_misp[eid].setdefault("url", url+"events/view/")
                            tmp_misp[eid].setdefault("date", date)
                            tmp_misp[eid].setdefault("level", event.get("threat_level_id",""))
                            tmp_misp[eid].setdefault("info", event.get("info", "").strip())
                            self.misper.update(tmp_misp)
                    self.lock.release()
            except Exception as e:
                log.error(e)

    def run(self):
        """Run analysis.
        @return: MISP results dict.
        """
        self.key = "misp"
        whitelist = list()
        self.iocs = deque()
        self.misper = dict()
        threads_list = list()
        self.lock = threading.Lock()

        results = dict()

        try:
            misp_config = Config("processing")
            if PYMISP and hasattr(misp_config, "misp"):
                url = misp_config.misp.get("url", "")
                apikey = misp_config.misp.get("apikey", "")
                threads = misp_config.misp.get("threads", "")
                if not threads:
                    threads = 5

                # load whitelist if exists
                if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
                    whitelist = Config("misp").whitelist.whitelist
                    if whitelist:
                        whitelist = [ioc.strip() for ioc in whitelist.split(",")]

                if url and apikey:
                    self.misp = PyMISP(url, apikey, False, "json")

                    for drop in self.results.get("dropped", []):
                        if drop.get("md5", "") and drop["md5"] not in self.iocs and drop["md5"] not in whitelist:
                            self.iocs.append(drop["md5"])

                    if self.results.get("target", {}).get("file", {}).get("md5", "") and self.results["target"]["file"]["md5"] not in whitelist:
                        self.iocs.append(self.results["target"]["file"]["md5"])
                    for block in self.results.get("network", {}).get("hosts", []):
                        if block.get("ip", "") and block["ip"] not in self.iocs and block["ip"] not in whitelist:
                            self.iocs.append(block["ip"])
                        if block.get("hostname", "") and block["hostname"] not in self.iocs and block["hostname"] not in whitelist:
                            self.iocs.append(block["hostname"])

                    if self.iocs:
                        for thread_id in xrange(int(threads)):
                            thread = threading.Thread(target=self.misper_thread, args=(url,))
                            thread.daemon = True
                            thread.start()

                            threads_list.append(thread)

                        for thread in threads_list:
                            thread.join()

                        if self.misper:
                            results = sorted(self.misper.values(), key=lambda x: datetime.strptime(x["date"], "%Y-%m-%d"), reverse=True)

                else:
                    log.error("MISP url or apikey not configurated")
            else:
                log.error("MISP config not exists")

        except Exception as e:
            log.exception(str(e))

        return results
