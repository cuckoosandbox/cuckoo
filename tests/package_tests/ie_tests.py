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


class TestIEPackage(unittest.TestCase, TestPackage):
    @classmethod
    def setUpClass(cls):    
        # init cuckoo
        db = Database()
        db.add_url(url="http://{}:{}/tests/test_samples/ie2.html".format(TestPackage.host_ip,TestPackage.http_port), package="ie", timeout=50)

        try:
            cuckoo_main(max_analysis_count=1)
        except Exception as e:
            print ("Error running analysis..", e)

        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                              "latest", "reports", "report.json")
        TestPackage.report = json.load(open(report_path, "rb"))  
        if(TestPackage.report.get("behavior").get("processes") == [] ):
            log.error("Failed to find a process")

    # check if downloaded executable is detected executed
    def test_processes(self):
        self.check_processes(TestPackage.report,["dl.exe"])