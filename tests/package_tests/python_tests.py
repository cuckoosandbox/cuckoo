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


class TestPythonPackage(unittest.TestCase, TestPackage):
    @classmethod
    def setUpClass(cls):    
        # init cuckoo
        db = Database()
        db.add_path(file_path=os.path.abspath("test_samples/python.py"), package="python", timeout=50)

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
        self.check_loaded_dlls(TestPackage.report, ["kernel32","msvcrt","ntdll.dll"])

    # check for dns requests
    def test_dns(self):
        self.check_dns_requests(TestPackage.report, ["google.com","reddit.com","twitter.com","facebook.com"])

    # check for network items
    def test_network(self):
        self.check_network(TestPackage.report, [{"getaddrinfo":{"NodeName":"google.com"}},
            {"getaddrinfo":{"NodeName":"reddit.com"}},
            {"getaddrinfo":{"NodeName":"twitter.com"}},
            {"InternetOpenUrlW":{"URL":"http://{}:{}/tests/test_samples/dl.c".format(TestPackage.host_ip,TestPackage.http_port)}},
            {"InternetReadFile":{}}])

    # check for registry entries / changes
    # dict: {"api-value":{"name-value":"value-value"}}
    def test_registry(self):
        self.check_registry(TestPackage.report,[ 
            {"RegCreateKeyExA":{"SubKey":"Software\\Cuckoo\\ReleaseTest"}},
            {"NtCreateKey":{"ObjectAttributes":"\\Registry\\Machine\\Software\\CuckooTest"}},
            {"NtQueryKey":{"KeyInformationClass":"2"}}],
            ["HKEY_LOCAL_MACHINE\\Software\\Cuckoo\\ReleaseTest"])

    # check for downloaded executable via http
    def test_http(self):
        self.check_http(TestPackage.report,["http://{}:{}/tests/test_samples/dl.exe".format(TestPackage.host_ip,TestPackage.http_port)])

    # check if file "test.exe" has been created
    def test_files(self):
        self.check_files(TestPackage.report, ["test.exe"])

    # check if file as dropped file
    def test_dropped_files(self):
        self.check_dropped_files(TestPackage.report, ["test.exe"])

    # check if downloaded executable is detected executed
    def test_processes(self):
        self.check_processes(TestPackage.report,["test.exe"])