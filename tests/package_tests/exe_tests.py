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


class TestExePackage(unittest.TestCase, TestPackage):
    @classmethod
    def setUpClass(cls):  
        # init cuckoo
        db = Database()
        db.add_path(file_path=os.path.abspath("test_samples/dl.exe"), package="exe", timeout=50)

        try:
            cuckoo_main(max_analysis_count=1)
        except Exception as e:
            print ("Error running analysis..", e)

        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                              "latest", "reports", "report.json")
        TestPackage.report = json.load(open(report_path, "rb"))  
        if(TestPackage.report.get("behavior").get("processes") == [] ):
            log.error("Failed to find a process")

    # check for loaded dlls
    def test_dlls(self):    
        self.check_loaded_dlls(TestPackage.report, ["ntdll.dll"])

    # check for dns requests
    def test_dns(self):
        self.check_dns_requests(TestPackage.report, ["facebook.com"])


    def test_socket(self):
        self.check_socket(TestPackage.report, [{"gethostbyname":{"Name":"facebook.com"}}])

    # check for network items
    def test_network(self):
        self.check_network(TestPackage.report, [
            {"InternetOpenUrlW":{"URL":"http://{}:{}/tests/test_samples/dl.c".format(TestPackage.host_ip,TestPackage.http_port)}},
            {"InternetReadFile":{}},])

    # check for registry entries / changes
    # dict: {"api-value":{"name-value":"value-value"}}
    def test_registry(self):
        self.check_registry(TestPackage.report,[ 
                    {"RegCreateKeyExA":{"SubKey":"Software\\Cuckoo\\DL.exe"}},
                    {"NtCreateKey":{"ObjectAttributes":"\\Registry\\Machine\\Software\\CuckooTest"}},
                    {"NtQueryKey":{"KeyInformationClass":"2"}},
                    {"NtEnumerateKey":{"Index":"0"}},
                    {"NtDeleteKey":{}}], 
                    ["HKEY_LOCAL_MACHINE\\Software\\Cuckoo\\DL.exe"]
            )     


    # check for downloaded executable via http
    def test_http(self):
        self.check_http(TestPackage.report,["http://{}:{}/tests/test_samples/dl.exe".format(TestPackage.host_ip,TestPackage.http_port)])

    # check if file "test.exe" has been created
    def test_files(self):
        self.check_files(TestPackage.report, ["downloaded.exe"])

    # check if file as dropped file
    def test_dropped_files(self):
        self.check_dropped_files(TestPackage.report, ["downloaded.exe"])  

    # check if downloaded executable is detected executed
    def test_processes(self):
        self.check_processes(TestPackage.report,["dl.exe"])