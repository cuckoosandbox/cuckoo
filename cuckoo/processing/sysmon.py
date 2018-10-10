import logging, os, re
import xml.etree.ElementTree as ET
import xmltodict

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__  = "@FernandoDoming"
__version__ = "1.0.0"

class Sysmon(Processing):

    def remove_noise(self, data):
        filtered_proc_creations_re = [
            r"C:\\Windows\\System32\\wevtutil\.exe\s+clear-log\s+microsoft-windows-(sysmon|powershell)\/operational",
            r"bin\\is32bit.exe",
            r"bin\\inject-(?:x86|x64).exe",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events microsoft-windows-powershell\/operational\s+\/rd:true\s+\/e:root\s+\/format:xml\s+\/uni:true",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events\s+microsoft-windows-sysmon\/operational\s+\/format:xml",
        ]

        filtered = []
        for event in data:
            is_filtered = False
            if event["System"]["EventID"] == "1":
                for p in filtered_proc_creations_re:
                    cmdline = event["EventData"]["Data"][9]["#text"]
                    if re.search(p, cmdline):
                        log.info("Supressed %s because it is noisy" % cmdline)
                        is_filtered = True

            if not is_filtered:
                filtered.append(event)

        return filtered

    def run(self):
        self.key = "sysmon"

        # Determine oldest sysmon log and remove the rest
        lastlog = os.listdir("%s/sysmon/" % self.analysis_path)
        lastlog.sort()
        lastlog = lastlog[-1]
        # Leave only the most recent file
        for f in os.listdir("%s/sysmon/" % self.analysis_path):
            if f != lastlog:
                try:
                    os.remove("%s/sysmon/%s" % (self.analysis_path, f))
                except:
                    log.error("Failed to remove sysmon file log %s" % f)

        os.rename(
            "%s/sysmon/%s" % (self.analysis_path, lastlog),
            "%s/sysmon/sysmon.xml" % self.analysis_path
        )

        data = None
        try:
            xml = open("%s/sysmon/sysmon.xml" % self.analysis_path).read()
            xml = xml.decode("latin1").encode("utf8")
            data = xmltodict.parse(xml)["Events"]["Event"]
        except Exception as e:
            raise CuckooProcessingError("Failed parsing sysmon.xml: %s" % e.message)

        return self.remove_noise(data)