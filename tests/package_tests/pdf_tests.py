import unittest 
import os 
import sys 
import logging 
import json 

from package_tests.package_test import TestPackage
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../")
sys.path.append(CUCKOO_ROOT)
from lib.cuckoo.core.database import Database
from cuckoo import cuckoo_main
log = logging.getLogger()


class TestPDFPackage(unittest.TestCase, TestPackage):
    @classmethod
    def setUpClass(cls):    
        # init cuckoo
        db = Database()
        db.add_path(file_path=os.path.abspath("test_samples/dl_exe.pdf"), package="pdf", timeout=50)

        try:
            cuckoo_main(max_analysis_count=1)
        except Exception as e:
            print ("Error running analysis..", e)

        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                              "latest", "reports", "report.json")
        TestPackage.report = json.load(open(report_path, "rb"))  
        if(TestPackage.report.get("behavior").get("processes") == [] ):
            log.error("Failed to find a process")

    # check for network items
    def test_network(self):
        self.check_network(TestPackage.report, [
                {"InternetConnectA":{"ServerName":TestPackage.host_ip}}, 
                {"InternetConnectA":{"ServerPort":TestPackage.http_port}},
                {"HttpOpenRequestA":{"Path":TestPackage.exe_http_path}}
            ])