# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import re

try:
    import requests
    HAVE_REQUESTS = True

    # Disable requests/urllib3 debug & info messages.
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
except ImportError:
    HAVE_REQUESTS = False

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.objects import File

class VirusTotalResourceNotScanned(CuckooOperationalError):
    """This resource has not been scanned yet."""

class VirusTotalAPI(object):
    """Wrapper to VirusTotal API."""

    FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"
    URL_REPORT = "https://www.virustotal.com/vtapi/v2/url/report"
    FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
    URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan"

    VARIANT_BLACKLIST = [
        "generic", "malware", "trojan", "agent", "win32", "multi", "w32",
        "trojanclicker", "trojware", "win", "a variant of win32", "trj",
        "susp", "dangerousobject", "backdoor", "clicker", "variant", "heur",
        "gen", "virus", "dropper", "generic suspicious", "spyware", "program",
        "suspectcrc", "corrupt", "behaveslike", "crypt", "adclicker",
        "troj", "injector", "cryptor", "packed", "adware", "macro", "msil4",
        "suspicious", "worm", "msil", "msword", "drop", "keygen", "office",
        "password", "malpack", "lookslike", "banker", "riskware", "unwanted",
        "unclassifiedmalware", "ransom", "trojan horse", "trjndwnlder",
        "trojandwnldr", "autorun", "trojandownloader", "trojandwnldr", "text",
        "download", "excel", "msilobfuscator", "rootkit", "application",
        "a variant of win64", "w97m", "shellcode", "o97m", "exploit",
        "x97m", "maliciousmacro", "downldr", "msexcel", "pp97m", "other",
        "trojandropper", "crypter", "a variant of msil", "macrodown",
        "trojanapt", "dwnldr", "downldexe", "dload", "trojanhorse", "toolbar",
        "mailer", "obfus", "obfuscator", "suspicious file", "optional",
        "suspected of trojan", "heuristic", "rogue", "virtool", "infostealer",
        "generic downloader", "generic malware", "undef", "inject", "packer",
        "generic backdoor", "word", "macosx", "hack", "unknown", "downloader",
        "trojanspy", "dldr", "msoffice", "osx32", "script", "stealer",
        "not a virus", "html", "expl", "shellkode", "downagent", "win64",
        "applicunwnt", "heur2", "ddos", "avkill", "servstart", "normal",
        "encoder", "w2km_dloader", "docdl", "w97m_dloadr", "mo97", "dloader",
        "x2km_dloadr", "w2km_dload", "w2km_dloade", "x2km_droppr", "exedown",
        "encodefeature", "docdrop", "mw97", "adload", "a variant of pp97m",
        "a variant of w97m", "badmacro", "bkdr", "docdrp", "exedrop",
        "generic trojan", "malcrypt", "malicious website", "ransomlock",
        "ransomcrypt", "reputation", "trojanransom", "pepatch", "risk",
        "adplugin", "webtoolbar", "malagent", "genmalicious", "vbinject",
        "vbcrypt", "inject2", "mdropper", "download3", "keylogger",
        "downloader11", "damaged", "file", "dldrop", "msil7", "injcrypt",
        "patched", "patchfile", "downware", "dropped",
    ]

    def __init__(self, apikey, timeout, scan=0):
        """Initialize VirusTotal API with the API key and timeout.
        @param api_key: virustotal api key
        @param timeout: request and response timeout
        @param scan: send file to scan or just get report
        """
        self.apikey = apikey
        self.timeout = timeout
        self.scan = scan

    def _request_json(self, url, **kwargs):
        """Wrapper around doing a request and parsing its JSON output."""
        if not HAVE_REQUESTS:
            raise CuckooOperationalError(
                "The VirusTotal processing module requires the requests "
                "library (install with `pip install requests`)")

        try:
            r = requests.post(url, timeout=self.timeout, **kwargs)
            return r.json() if r.status_code == 200 else {}
        except (requests.ConnectionError, ValueError) as e:
            raise CuckooOperationalError("Unable to fetch VirusTotal "
                                         "results: %r" % e.message)

    def _get_report(self, url, resource, summary=False):
        """Fetch the report of a file or URL."""
        data = dict(resource=resource, apikey=self.apikey)

        r = self._request_json(url, data=data)

        # This URL has not been analyzed yet - send a request to analyze it
        # and return with the permalink.
        if not r.get("response_code"):
            if self.scan:
                raise VirusTotalResourceNotScanned
            else:
                return {
                    "summary": {
                        "error": "resource has not been scanned yet",
                    }
                }

        results = {
            "summary": {
                "positives": r.get("positives", 0),
                "permalink": r.get("permalink"),
                "scan_date": r.get("scan_date"),
            },
        }

        # For backwards compatibility.
        results.update(r)

        if not summary:
            results["scans"] = {}
            results["normalized"] = []

            # Embed all VirusTotal results into the report.
            for engine, signature in r.get("scans", {}).items():
                signature["normalized"] = self.normalize(signature["result"])
                results["scans"][engine.replace(".", "_")] = signature

            # Normalize each detected variant in order to try to find the
            # exact malware family.
            norm_lower = []
            for signature in results["scans"].values():
                for normalized in signature["normalized"]:
                    if normalized.lower() not in norm_lower:
                        results["normalized"].append(normalized)
                        norm_lower.append(normalized.lower())

        return results

    def url_report(self, url, summary=False):
        """Get the report of an existing URL scan.
        @param url: URL
        @param summary: if you want a summary report"""
        return self._get_report(self.URL_REPORT, url, summary)

    def file_report(self, filepath, summary=False):
        """Get the report of an existing file scan.
        @param filepath: file path
        @param summary: if you want a summary report"""
        resource = File(filepath).get_md5()
        return self._get_report(self.FILE_REPORT, resource, summary)

    def url_scan(self, url):
        """Submit a URL to be scanned.
        @param url: URL
        """
        data = dict(apikey=self.apikey, url=url)
        r = self._request_json(self.URL_SCAN, data=data)
        return dict(summary=dict(permalink=r.get("permalink")))

    def file_scan(self, filepath):
        """Submit a file to be scanned.
        @param filepath: file path
        """
        data = dict(apikey=self.apikey)
        files = {"file": open(filepath, "rb")}
        r = self._request_json(self.FILE_SCAN, data=data, files=files)
        return dict(summary=dict(permalink=r.get("permalink")))

    def normalize(self, variant):
        """Normalize the variant name provided by an Anti Virus engine. This
        attempts to extract the useful parts of a variant name by stripping
        all the boilerplate stuff from it."""
        if not variant:
            return []

        ret = []

        # Handles "CVE-2012-1234", "CVE2012-1234".
        cve = re.search("CVE[-_]?(\\d{4})[-_](\\d{4})", variant)
        if cve:
            ret.append("CVE-%s-%s" % (cve.group(1), cve.group(2)))

        # Handles "CVE121234".
        cve = re.search("CVE(\\d{2})(\\d{4})", variant)
        if cve:
            ret.append("CVE-20%s-%s" % (cve.group(1), cve.group(2)))

        for word in re.split("[\\.\\,\\-\\(\\)\\[\\]/!:_]", variant):
            word = word.strip()
            if len(word) < 4:
                continue

            if word.lower() in self.VARIANT_BLACKLIST:
                continue

            # Random hashes that are specific to this file.
            if re.match("[a-fA-F0-9]+$", word):
                continue

            # Family names followed by "potentially unwanted".
            if re.match("[a-zA-Z]{1,2} potentially unwanted", word.lower()):
                continue

            ret.append(word)
        return ret
