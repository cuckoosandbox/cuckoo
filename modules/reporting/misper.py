# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

try:
    from pymisp import PyMISP

    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError

class MISPER(Report):
    """Create MISP event from analysis report"""

    def run(self, results):
        if not self.task.options.get("misper"):
            return

        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The Notification reporting module requires the requests library (install with `pip install requests`)"
            )

        if not HAVE_MISP:
            raise CuckooDependencyError(
                "Unable to import PyMISP (install with `pip install pymisp`)"
            )

        self.url = self.options["url"]
        self.apikey = self.options["apikey"]
        self.results = results

        # list of dropped extensions that can be uploaded
        dropped_ext = [
            "bat", "bin", "cmd", "com", "dll", "exe", "hta", "jar", "js",
            "lnk", "msi", "pif", "ps", "rar",
            "reg", "scf", "scr", "sys", "swf", "vb", "ws", "zip"
        ]

        if not self.url or not self.apikey:
            raise CuckooReportError(
                "Please configure the URL and API key for your MISP instance."
            )

        try:
            misp = PyMISP(self.url, self.apikey, ssl=False, out_type="json",
                          debug=False, proxies=None)
        except Exception as e:
            raise CuckooReportError(
                "Failed to establish connection to MISP: %s" % e
            )

        # file submitted to MISP
        if "file" in self.results.get("target", {}).get("category", {}):
            match = misp.search_all(
                self.results.get("target", {}).get("file", {}).get("md5", {}))
            info = self.results.get("target", {}).get("file", {}).get("name",
                                                                      {})

        # URL submitted to MISP
        if "url" in self.results.get("target", {}).get("category", {}):
            match = misp.search_all(
                self.results.get("target", {}).get("url", {}))
            info = self.results.get("target", {}).get("url", {})

        # check if file/URL already submitted to MISP
        if "response" in match:
            print "MISPER: %s has already been submitted to MISP" % info
            return

        try:
            # Create MISP event
            misp_e = misp.new_event(distribution=1, threat_level_id=1,
                                    analysis=0, info=info)

        except Exception as e:
            raise CuckooReportError(
                "Failed creating MISP event: %s" % e
            )

        try:
            # upload sample malware to MISP
            misp.upload_sample(
                filename=self.results.get("target", {}).get("file", {}).get(
                    "name", {}),
                filepath=self.results.get("target", {}).get("file", {}).get(
                    "path", {}),
                event_id=misp_e["Event"]["id"], distribution=5, to_ids=True,
                category="Payload delivery",
                comment=self.results["target"]["file"]["type"], info="",
                analysis=0,
                threat_level_id=1)
        except Exception as e:
            raise CuckooReportError(
                "Failed uploading MISP sample: %s" % e
            )

        try:
            # add URLs from DNS and process memory to MISP
            if "procmemory" in self.results:
                for process in self.results.get("procmemory", {}):
                    if "network" in self.results and "dns" in self.results.get(
                            "network", {}):
                        for dns in self.results.get("network", {}).get("dns",
                                                                       {}):
                            misp.add_url(misp_e, url=dns.get("request", {}),
                                         category="Network activity",
                                         to_ids=True,
                                         comment="extracted from dns",
                                         distribution=5, proposal=False)

                    if "signatures" in self.results:
                        for signature in self.results.get("signatures", {}):
                            for mark in signature.get("marks", []):
                                if mark.get("category", {}) == "url":
                                    url = mark["ioc"]
                                    misp.add_url(misp_e, url=url,
                                                 category="Network activity",
                                                 to_ids=True,
                                                 comment="extracted from process memory",
                                                 distribution=5,
                                                 proposal=False)
        except Exception as e:
            raise CuckooReportError(
                "Failed adding URL/DNS to MISP event: %s" % e
            )

        try:
            # add mutex to MISP
            if "behavior" in self.results and "summary" in self.results.get(
                    "behavior", {}) \
                    and "mutex" in self.results.get("behavior", {}).get(
                        "summary", {}):
                for mutex in self.results.get("behavior", {}).get("summary",
                                                                  {}).get(
                        "mutex", {}):
                    misp.add_mutex(misp_e, mutex=mutex,
                                   category="Artifacts dropped", to_ids=True,
                                   comment="",
                                   distribution=5, proposal=False)
        except Exception as e:
            raise CuckooReportError(
                "Failed adding mutex to MISP event: %s" % e
            )

        try:
            # upload dropped files to MISP
            if "dropped" in self.results:
                for dropped in self.results.get("dropped", {}):
                    ext = os.path.splitext(dropped.get("name", {}))[1].lstrip(
                        ".").lower()
                    type = dropped.get("type", {})
                    if ext in dropped_ext or "PE32" in type:
                        misp.upload_sample(
                            filename=dropped.get("name", {}).split("_")[1],
                            filepath=dropped.get("path", {}),
                            event_id=misp_e["Event"]["id"], distribution=5,
                            to_ids=True,
                            category="Artifacts dropped",
                            comment=type, info="",
                            analysis=0, threat_level_id=1)
        except Exception as e:
            raise CuckooReportError(
                "Failed adding dropped file to MISP event: %s" % e
            )

        try:
            # upload dropped buffer files to MISP
            if "buffer" in self.results:
                for dropped_buffer in self.results.get("buffer", {}):
                    type = dropped_buffer.get("type", {})
                    if "PE32" in type:
                        misp.upload_sample(
                            filename=dropped_buffer.get("name", {}),
                            filepath=dropped_buffer.get("path", {}),
                            event_id=misp_e["Event"]["id"], distribution=5,
                            to_ids=True,
                            category="Artifacts dropped",
                            comment="%s - %s" % (type, "dropped buffer"),
                            info="", analysis=0,
                            threat_level_id=1)
        except Exception as e:
            raise CuckooReportError(
                "Failed adding dropped buffer to MISP event: %s" % e
            )

        try:
            # add registry key|value to MISP
            if "signatures" in self.results:
                for signature in self.results.get("signatures", {}):
                    if signature.get("name", {}) == "persistence_autorun":
                        for mark in signature.get("marks", []):
                            if mark.get("category", {}) == "registry":
                                misp.add_regkey(misp_e, regkey=None,
                                                rvalue=mark.get("ioc", {}),
                                                category="Persistence mechanism",
                                                to_ids=True, comment="",
                                                distribution=5,
                                                proposal=False)

        except Exception as e:
            raise CuckooReportError(
                "Failed adding registry key to MISP event: %s" % e
            )

        try:
            # add PDB to MISP
            if "signatures" in self.results:
                for signature in self.results.get("signatures", {}):
                    if signature.get("name", {}) == "has_pdb":
                        for mark in signature.get("marks", []):
                            if mark.get("category", {}) == "pdb_path":
                                value = mark.get("ioc", {}).split("\\")[-1]
                                misp.add_named_attribute(misp_e,
                                                         category="Artifacts dropped",
                                                         type_value="pdb",
                                                         value=value,
                                                         to_ids=True,
                                                         comment="",
                                                         distribution=5,
                                                         proposal=False)

        except Exception as e:
            raise CuckooReportError(
                "Failed adding PDB to MISP event: %s" % e
            )
