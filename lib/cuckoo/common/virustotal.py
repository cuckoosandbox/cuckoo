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
from modules.processing.cuckooml import Instance

class VirusTotalResourceNotScanned(CuckooOperationalError):
    """This resource has not been scanned yet."""

class VirusTotalAPI(object):
    """Wrapper to VirusTotal API."""

    FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"
    URL_REPORT = "https://www.virustotal.com/vtapi/v2/url/report"
    FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
    URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan"

    VARIANT_BLACKLIST = [
        "a", "variant", "of", "file", "generic", "not",
        "file", "other", "potentially", "text", "optional",
        "agent", "susp", "dangerousobject", "dangerous", "object", "corrupt",
        "lookslike", "looks", "like", "unclassifiedmalware", "unclassified",
        "malware", "horse", "application", "program", "malicious", "small",
        "behaveslike", "behaves", "behave", "heuristic", "reputation",
        "suspected", "undef", "unknown", "normal", "damaged",
        "malagent", "packer", "password", "patched", "patchfile", "pepatch",
        "servstart", "gen", "generikcd", "genmalicious", "heur", "heur2",
        "applicunwnt", "autorun", "avkill", "generik",
        "encodefeature", "encoder", "infostealer", "keylogger", "obfus",
        "website", "plugin", "webtoolbar", "packed", "toolbar",
        "obfuscator", "stealer", "suspectcrc"
    ]

    FIX_BLACKLIST = [  # prefixes&suffixes
        "apt", "ms",
        "vb", "mal", "pack", "exe", "enz"  # "doc"
    ]

    PLATFORMS = {
        # Operating systems
        "androidos": "Android operating system",
        "dos": "MS-DOS platform",
        "epoc": "Psion devices",
        "freebsd": "FreeBSD platform",
        "iphoneos": "iPhone operating system",
        "linux": "Linux platform",
        "macos": "MAC 9.x platform or earlier",
        "macos_x": "MacOS X or later",
        "os2": "OS2 platform",
        "palm": "Palm operating system",
        "solaris": "System V-based Unix platforms",
        "sunos": "Unix platforms 4.1.3 or lower",
        "symbos": "Symbian operating system",
        "unix": "general Unix platforms",
        "win16": "Win16 (3.1) platform",
        "win2k": "Windows 2000 platform",
        "win32": "Windows 32-bit platform",
        "win64": "Windows 64-bit platform",
        "win95": "Windows 95, 98 and ME platforms",
        "win98": "Windows 98 platform only",
        "wince": "Windows CE platform",
        "winnt": "WinNT",
        # Scripting languages
        "abap": "Advanced Business Application Programming scripts",
        "alisp": "ALisp scripts",
        "amipro": "AmiPro script",
        "ansi": "American National Standards Institute scripts",
        "applescript": "compiled Apple scripts",
        "asp": "Active Server Pages scripts",
        "autoit": "AutoIT scripts",
        "bas": "Basic scripts",
        "bat": "Basic scripts",
        "corelscript": "Corelscript scripts",
        "hta": "HTML Application scripts",
        "html": "HTML Application scripts",
        "inf": "Install scripts",
        "irc": "mIRC/pIRC scripts",
        "java": "Java binaries (classes)",
        "js": "Javascript scripts",
        "logo": "LOGO scripts",
        "mpb": "MapBasic scripts",
        "msh": "Monad shell scripts",
        "msil": ".Net intermediate language scripts",
        "perl": "Perl scripts",
        "php": "Hypertext Preprocessor scripts",
        "python": "Python scripts",
        "sap": "SAP platform scripts",
        "sh": "Shell scripts",
        "vba": "Visual Basic for Applications scripts",
        "vbs": "Visual Basic scripts",
        "winbat": "Winbatch scripts",
        "winhlp": "Windows Help scripts",
        "winreg": "Windows registry scripts",
        # Macros
        "a97m": "Access 97, 2000, XP, 2003, 2007, and 2010 macros",
        "he": "macro scripting",
        "o97m": "Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that \
            affect Word, Excel, and Powerpoint",
        "pp97m": "PowerPoint 97, 2000, XP, 2003, 2007, and 2010 macros",
        "v5m": "Visio5 macros",
        "w1m": "Word1Macro",
        "w2m": "Word2Macro",
        "w97m": "Word 97, 2000, XP, 2003, 2007, and 2010 macros",
        "wm": "Word 95 macros",
        "x97m": "Excel 97, 2000, XP, 2003, 2007, and 2010 macros",
        "xf": "Excel formulas",
        "xm": "Excel 95 macros",
        # Other file types
        "asx": "XML metafile of Windows Media .asf files",
        "hc": "HyperCard Apple scripts",
        "mime": "MIME packets",
        "netware": "Novell Netware files",
        "qt": "Quicktime files",
        "sb": "StarBasic (Staroffice XML) files",
        "swf": "Shockwave Flash files",
        "tsql": "MS SQL server files",
        "xml": "XML files"
    }

    ALTERNATIVE_PLATFORMS = {
        "multi": "multi",
        "macro": "o97m",
        "office": "o97m",
        "excel": "x97m",
        "word": "w97m",
        "powerpoint": "pp97m",
        "access": "a97m",
        "msil": "msil"
    }

    TYPES = [
        "adware",
        "behavior",
        "browsermodifier",
        "constructor",
        "ddos",
        "dialer",
        "dos",
        "exploit",
        "hacktool",
        "joke",
        "misleading",
        "monitoringtool",
        "program",
        "pws",
        "ransom",
        "remoteaccess",
        "riskware",
        "rogue",
        "rootkit",
        "settingsmodifier",
        "softwarebundler",
        "spammer",
        "spoofer",
        "tool",
        "trojan",
        "clicker",
        "downloader",
        "dropper",
        "notifier",
        "proxy",
        "spyware",
        "backdoor",
        "virtool",
        "virus",
        "worm"
    ]

    TROJANS = [
        "clicker",
        "downloader",
        "dropper",
        "notifier",
        "proxy",
        "spyware",
        "backdoor"
    ]

    RISKWARE = [
        "adware",
        "softwarebundler",
        "hacktool",
        "rogue"
    ]

    MAPPING = {
        "click": "clicker",
        "spy": "spyware",
        "adware": "adware",
        "ad": "adware",
        "bundler": "softwarebundler",
        "hack": "hacktool",
        "hackkms": "hacktool",
        "kms": "hacktool",
        "hacktool": "hacktool",
        "rogue": "rogue",
        "rogueware": "rogue",
        "riskware": "riskware",
        "risk": "riskware",
        "grayware": "riskware",
        "hktl": "riskware",
        "keygen": "riskware",
        "onlinegames": "riskware",
        "scareware": "riskware",
        "startpage": "riskware",
        "suspicious": "riskware",
        "unwanted": "riskware",
        "backdoor": "backdoor",
        "bkdr": "backdoor",
        "genericbackdoor": "backdoor",
        "trojbackdoor": "backdoor",
        "trojan": "trojan",
        "banker": "trojan",
        "injector": "trojan",
        "inject": "trojan",
        "inj": "trojan",
        "tr": "trojan",
        "trj": "trojan",
        "trjn": "trojan",
        "troj": "trojan",
        "trojware": "trojan",
        "downloader": "downloader",
        "loader": "downloader",
        "exedown": "downloader",
        "dldr": "downloader",
        "dloader": "downloader",
        "dloadr": "downloader",
        "downldexe": "downloader",
        "downldr": "downloader",
        "down": "downloader",
        "dload": "downloader",
        "dloade": "downloader",
        "dl": "downloader",
        "download": "downloader",
        "downagent": "downloader",
        "downware": "downloader",
        "dwnldr": "downloader",
        "dwnlder": "downloader",
        "load": "downloader",
        "muldown": "downloader",
        "ransom": "ransom",
        "crypt": "ransom",
        "crypter": "ransom",
        "cryptor": "ransom",
        "krypt": "ransom",
        "kryptik": "ransom",
        "lock": "ransom",
        "ransom": "ransom",
        "ransomcrypt": "ransom",
        "ransomlock": "ransom",
        "rootkit": "rootkit",
        "rkit": "rootkit",
        "rtk": "rootkit",
        "sys": "rootkit",
        # extension
        "expl": "exploit",
        "dropper": "dropper",
        "mdropper": "dropper",
        "dropped": "dropper",
        "drop": "dropper",
        "drp": "dropper",
        "mailer": "mailer"
    }

    TEMPLATE = "{type}:{platform}/{family}.{variant}!{information}"

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
            results["normalized"] = {
                "cve": "",
                "platform": "",
                "metatype": "",
                "type": "",
                "family": ""
            }

            # Embed all VirusTotal results into the report.
            for engine, signature in r.get("scans", {}).items():
                signature["normalized"] = self.normalize(signature["result"])
                results["scans"][engine.replace(".", "_")] = signature

            # Normalize each detected variant in order to try to find the
            # exact malware family.
            norm_lower = {
                "cve": [],
                "platform": [],
                "metatype": [],
                "type": [],
                "family": [],
            }
            for signature in results["scans"].values():
                for label_type in signature["normalized"]:
                    norm_lower[label_type] += signature["normalized"][label_type]

            labeller = Instance()
            for label_type in norm_lower:
                labeller.label_sample(norm_lower[label_type])
                results["normalized"][label_type] = labeller.label

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

    def detect_platform(self, tokens):
        """Guess platform affected by malware based on tokenised VT name."""

        def compare_platforms(platform_list, token):
            """Check whether token is one of predefined platforms."""
            platform = ""
            for os in platform_list:
                if token.startswith(os):
                    return os
                if os.startswith(token):
                    return os
            for os in platform_list:
                if os in token:
                    return os
            return platform

        platform = []
        remaining_tokens = []

        while tokens:
            token = tokens.pop()

            # Check for alternative platforms
            cp = compare_platforms(self.ALTERNATIVE_PLATFORMS, token)
            if cp:
                platform.append(self.ALTERNATIVE_PLATFORMS[cp])
                remaining_tokens += token.split(cp)
                continue

            # Check for OS
            cp = compare_platforms(self.PLATFORMS, token)
            if cp:
                platform.append(cp)
                remaining_tokens += token.split(cp)
                continue

            # Check for MS Windows name variants: "win" and "w" instead of "win"
            if "win" in token:
                platform.append("win")
                remaining_tokens += token.split("win")
                continue

            # find windows edition encoded as "w.."; if the string is followed
            # by "m" it's a macro and not an OS
            found = re.findall(r"w(16|32|64|95|98|2k|ce|nt|bat|hlp|reg)(?!m)",
                               token)
            # WARNING: only works for the first match
            if found:
                platform.append("win" + found[0])
                remaining_tokens += token.split("w"+found[0])
                continue

            # Handle MS Office macros # x w pp a
            # Office 2K
            found = re.findall(r"([a-zA-Z])2km", token)
            if found:
                platform.append(found[0] + "97m")
                remaining_tokens += token.split(found[0] + "2km")
                continue

            # Office 97 with missing "m"
            found = re.findall(r"([a-zA-Z]97)", token)
            if found:
                platform.append(found[0] + "m")
                remaining_tokens += token.split(found[0] + "m")
                continue

            # If none of the above apply transfer the token
            remaining_tokens.append(token)

        # Remove empty strings tokens
        tokens = [t.strip() for t in remaining_tokens if t.strip()]

        return platform, tokens

    def clean_tokens(self, tokens):
        """Cleans tokenised malware name based on VARIANT_BLACKLIST.
        The conditions for removing a substring are: exact match, prefix, and
        suffix."""

        def resolve_mapping(self, mapping, token):
            """Find possible tokens mappings from longest to the shortest
            string according to predefined MAPPING lookup table."""
            # TODO: pick the most probable abbreviation combination i.e. the one
            #       that uses all of the sub-tokens and not only a few
            #       e.g. "adload"
            new_token = ""
            old_tokens = []

            for key in mapping:
                # if the token is constructed from multiple tokens
                # startswith and endswith should be separated here
                if token.startswith(key):
                    new_token = self.MAPPING[key]
                    old_tokens = token.split(key)
                    break
                if token.endswith(key):
                    new_token = self.MAPPING[key]
                    old_tokens = token.split(key)
                    break
                if key in token:
                    tokens_iter3.append(self.MAPPING[key])
                    old_tokens = token.split(key)
                    break

            # clean old_tokens from empty strings
            old_tokens = [t.strip() for t in old_tokens if t.strip()]

            return new_token, old_tokens

        # Check 1:1 mappings
        tokens_iter0 = []
        for token in tokens:
            if token in self.MAPPING:
                tokens_iter0.append(self.MAPPING[token])
            else:
                tokens_iter0.append(token)

        # Handle blacklisted tokens and random (hex) hashes
        tokens_iter1 = []
        for token in tokens_iter0:
            if token not in self.VARIANT_BLACKLIST and \
                    token not in self.FIX_BLACKLIST and \
                    not token.isdigit() and \
                    not re.match("[a-fA-F0-9]+$", token) and \
                    len(token) > 2:
                tokens_iter1.append(token)

        tokens_iter2 = []
        for token in tokens_iter1:
            for variant in self.FIX_BLACKLIST:
                new_token = ""
                if token.startswith(variant):
                    new_token = token.split(variant)[-1]
                    tokens_iter2.append(new_token)
                    break
                if token.endswith(variant):
                    new_token = token.split(variant)[0]
                    tokens_iter2.append(new_token)
                    break

            # When none of the above apply keep the token
            if not new_token:
                tokens_iter2.append(token)

        # Get proper names according to predefined mapping
        sorted_mapping = sorted(self.MAPPING, key=len, reverse=True)
        tokens_iter3 = []
        while tokens_iter2:
            token = tokens_iter2.pop()

            if token in self.MAPPING:
                tokens_iter3.append(self.MAPPING[token])
                continue

            new_token, old_tokens = resolve_mapping(self, sorted_mapping, token)
            tokens_iter2 += old_tokens
            if new_token:
                tokens_iter3.append(new_token)
            # If no new token found leave the token untouched
            else:
                tokens_iter3.append(token)

        # Remove tokens up to 2 letters and the blacklisted ones
        tokens_iter4 = [t for t in tokens_iter3 if len(t) > 2 and
                        t not in self.VARIANT_BLACKLIST]

        return tokens_iter4

    def normalize(self, variant):
        """Normalize the variant name provided by an Anti Virus engine. This
        attempts to extract the useful parts of a variant name by stripping
        all the boilerplate stuff from it."""
        ret = {
            "cve": [],
            "platform": [],
            "metatype": [],
            "type": [],
            "family": []
        }

        if not variant:
            return ret

        # Handles "CVE-2012-1234", "CVE2012-1234".
        cve = re.search("CVE[-_]?(\\d{4})[-_](\\d{4})", variant)
        if cve:
            ret["cve"].append("CVE-%s-%s" % (cve.group(1), cve.group(2)))

        # Handles "CVE121234".
        cve = re.search("CVE(\\d{2})(\\d{4})", variant)
        if cve:
            ret["cve"].append("CVE-20%s-%s" % (cve.group(1), cve.group(2)))

        # Split variant into tokens based on any punctuation symbol including _
        vt_name = variant.encode("ascii", "ignore").lower()
        tokens = re.findall(r"[a-zA-Z0-9]+", vt_name)

        tokens = self.clean_tokens(tokens)
        ret["platform"], tokens = self.detect_platform(tokens)

        # Discard too short tokens which are not recognised
        tokens = [t for t in tokens if len(t) >= 4]

        for token in tokens:
            # Get metatype: trojan & riskware
            if (token == "trojan" or token in self.TROJANS) and\
                    "trojan" not in ret["metatype"]:
                ret["metatype"].append("trojan")
            if (token == "riskware" or token in self.RISKWARE) and\
                    "riskware" not in ret["metatype"]:
                ret["metatype"].append("riskware")

            # Get type
            if token != "trojan" and token != "riskware" and \
                    token in self.TYPES:
                ret["type"].append(token)

            # Get family
            if token != "trojan" and token != "riskware" and \
                    token not in self.TYPES:
                ret["family"].append(token)

        return ret
