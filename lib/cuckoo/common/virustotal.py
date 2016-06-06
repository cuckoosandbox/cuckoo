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
        "a", "variant", "of", "file", "generic", "not", "suspicious",
        "file", "other", "potentially", "unwanted", "text", "optional",
        "agent", "susp", "dangerousobject", "dangerous", "object", "corrupt",
        "lookslike", "looks", "like", "unclassifiedmalware", "unclassified",
        "malware", "horse", "application", "program", "malicious", "small",
        "behaveslike", "behaves", "behave", "heuristic", "reputation",
        "suspected", 'undef', 'unknown', 'normal', 'damaged',
        'malagent', 'packer', 'password', 'patched', 'patchfile', 'pepatch',
        'servstart', 'gen', 'generikcd', 'genmalicious', 'heur', 'heur2',
        'adclicker', 'adload', 'applicunwnt', 'autorun', 'avkill', 'generik',
        'encodefeature', 'encoder', 'infostealer', 'keylogger', 'obfus',
        "website", "adplugin", "webtoolbar", "packed", "toolbar",
        'obfuscator', 'stealer', 'suspectcrc'
    ]

    FIX_BLACKLIST = [ # prefixes&suffixes
        'apt', "ms",
        'vb', 'mal', 'pack', 'exe', 'enz' # 'doc'
    ]

    PLATFORMS = {
        # Operating systems
        'androidos': 'Android operating system',
        'dos': 'MS-DOS platform',
        'epoc': 'Psion devices',
        'freebsd': 'FreeBSD platform',
        'iphoneos': 'iPhone operating system',
        'linux': 'Linux platform',
        'macos': 'MAC 9.x platform or earlier',
        'macos_x': 'MacOS X or later',
        'os2': 'OS2 platform',
        'palm': 'Palm operating system',
        'solaris': 'System V-based Unix platforms',
        'sunos': 'Unix platforms 4.1.3 or lower',
        'symbos': 'Symbian operating system',
        'unix': 'general Unix platforms',
        'win16': 'Win16 (3.1) platform',
        'win2k': 'Windows 2000 platform',
        'win32': 'Windows 32-bit platform',
        'win64': 'Windows 64-bit platform',
        'win95': 'Windows 95, 98 and ME platforms',
        'win98': 'Windows 98 platform only',
        'wince': 'Windows CE platform',
        'winnt': 'WinNT',
        # Scripting languages
        'abap': 'Advanced Business Application Programming scripts',
        'alisp': 'ALisp scripts',
        'amipro': 'AmiPro script',
        'ansi': 'American National Standards Institute scripts',
        'applescript': 'compiled Apple scripts',
        'asp': 'Active Server Pages scripts',
        'autoit': 'AutoIT scripts',
        'bas': 'Basic scripts',
        'bat': 'Basic scripts',
        'corelscript': 'Corelscript scripts',
        'hta': 'HTML Application scripts',
        'html': 'HTML Application scripts',
        'inf': 'Install scripts',
        'irc': 'mIRC/pIRC scripts',
        'java': 'Java binaries (classes)',
        'js': 'Javascript scripts',
        'logo': 'LOGO scripts',
        'mpb': 'MapBasic scripts',
        'msh': 'Monad shell scripts',
        'msil': '.Net intermediate language scripts',
        'perl': 'Perl scripts',
        'php': 'Hypertext Preprocessor scripts',
        'python': 'Python scripts',
        'sap': 'SAP platform scripts',
        'sh': 'Shell scripts',
        'vba': 'Visual Basic for Applications scripts',
        'vbs': 'Visual Basic scripts',
        'winbat': 'Winbatch scripts',
        'winhlp': 'Windows Help scripts',
        'winreg': 'Windows registry scripts',
        # Macros
        'a97m': 'Access 97, 2000, XP, 2003, 2007, and 2010 macros',
        'he': 'macro scripting',
        'o97m': 'Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and Powerpoint',
        'pp97m': 'PowerPoint 97, 2000, XP, 2003, 2007, and 2010 macros',
        'v5m': 'Visio5 macros',
        'w1m': 'Word1Macro',
        'w2m': 'Word2Macro',
        'w97m': 'Word 97, 2000, XP, 2003, 2007, and 2010 macros',
        'wm': 'Word 95 macros',
        'x97m': 'Excel 97, 2000, XP, 2003, 2007, and 2010 macros',
        'xf': 'Excel formulas',
        'xm': 'Excel 95 macros',
        # Other file types
        'asx': 'XML metafile of Windows Media .asf files',
        'hc': 'HyperCard Apple scripts',
        'mime': 'MIME packets',
        'netware': 'Novell Netware files',
        'qt': 'Quicktime files',
        'sb': 'StarBasic (Staroffice XML) files',
        'swf': 'Shockwave Flash files',
        'tsql': 'MS SQL server files',
        'xml': 'XML files'
    }

    ALTERNATIVE_PLATFORMS = {
        "multi":"multi",
        "macro":"o97m",
        "office":"o97m",
        "excel":"x97m",
        "word":"w97m",
        "powerpoint":"pp97m",
        "access":"a97m",
        "msil":"msil"
    }

    TYPES = [
        'Adware', #adware -> riskware
        'Backdoor',
        'Behavior',
        'BrowserModifier',
        'Constructor',
        'DDoS',
        'Dialer',
        'DoS',
        'Exploit', #
        'HackTool', ##hack->riskware
        'Joke',
        'Misleading',
        'MonitoringTool',
        'Program',
        'PWS',
        'Ransom', #
        'RemoteAccess',
        'Rogue',
        'Rootkit', # added # count #
        'SettingsModifier',
        'SoftwareBundler',
        'Spammer',
        'Spoofer',
        'Spyware',
        'Tool',
        'Trojan', #
        'TrojanClicker',
        'TrojanDownloader', #
        'TrojanDropper', #
        'TrojanNotifier',
        'TrojanProxy',
        'TrojanSpy',
        'VirTool',
        'Virus',
        'Worm' #
    ]

    MAPPING = {
        "riskware":"riskware",
        "risk":"riskware",
        "adware":"riskware",
        "bundler":"riskware",
        "grayware":"riskware",
        "hack":"riskware",
        "hackkms":"riskware",
        "hacktool":"riskware",
        "hktl":"riskware",
        "keygen":"riskware",
        "kms":"riskware",
        "onlinegames":"riskware",
        "rogue":"riskware",
        "rogueware":"riskware",
        "scareware":"riskware",
        "startpage":"riskware",
        "suspicious":"riskware",
        "unwanted":"riskware",
        "trojan":"trojan",
        "backdoor":"trojan",
        "genericbackdoor":"trojan",
        "banker":"trojan",
        "bkdr":"trojan",
        "trojbackdoor":"trojan",
        "injector":"trojan",
        "inject":"trojan",
        "inj":"trojan",
        "tr":"trojan",
        "trj":"trojan",
        "trjn":"trojan",
        "troj":"trojan",
        "trojware":"trojan",
        "downloader":"downloader",
        "loader":"downloader",
        "exedown":"downloader",
        "dldr":"downloader",
        "dloader":"downloader",
        "dloadr":"downloader",
        "downldexe":"downloader",
        "downldr":"downloader",
        "down":"downloader",
        "dload":"downloader",
        "dloade":"downloader",
        "dl":"downloader",
        "download":"downloader",
        "downagent":"downloader",
        "downware":"downloader",
        "dwnldr":"downloader",
        "dwnlder":"downloader",
        "load":"downloader",
        "muldown":"downloader",
        "ransom":"ransom",
        "crypt":"ransom",
        "crypter":"ransom",
        "cryptor":"ransom",
        "krypt":"ransom",
        "kryptik":"ransom",
        "lock":"ransom",
        "ransom":"ransom",
        "ransomcrypt":"ransom",
        "ransomlock":"ransom",
        "rootkit":"rootkit",
        "rkit":"rootkit",
        "rtk":"rootkit",
        "sys":"rootkit",
        # extension
        "expl":"exploit",
        "dropper":"dropper",
        "mdropper":"dropper",
        "dropped":"dropper",
        "drop":"dropper",
        "drp":"dropper",
        "mailer":"mailer"
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



    def detect_platform(self, tokens):
        """Guess platform affected by malware based on tokenised VT name."""

        def compare_platforms(self, token):
            """Check whether token is one of predefined platforms."""
            platform = ""
            for os in self.PLATFORMS:
                if os in token:
                    return os
            return platform

        platform = "unknown"
        used_token = ""
        remaining_tokens = []

        # TODO: only the first platform that is found is returned
        for token in tokens:
            # Check for multiplatform
            if "multi" in token:
                platform = "multi"
                used_token = token
                remaining_tokens = token.split("multi")
                break

            # Check for MS Office suite

            # Check for OS
            cp = compare_platforms(token)
            if cp:
                platform = cp
                used_token = token
                remaining_tokens = token.split(cp)
                break

            # Check for MS Windows name variants: "win" and "w" instead of "win"
            if "win" in token:
                platform = "win"
                used_token = token
                remaining_tokens = token.split("win")
                break

            found = re.findall(r"w([0-9]{2}|2k|ce|nt|bat|hlp|reg)", token)
            # TODO: what if 2 or more matches are found
            if found:
                platform = "win" + found[0]
                used_token = token
                remaining_tokens = token.split("w"+found[0])
                break

        # Clean-up tokens
        if used_token:
            tokens.remove(token)
            # remove empty strings from t
            tokens += [t.strip() for t in remaining_tokens if t.strip()]

        return platform, tokens


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
