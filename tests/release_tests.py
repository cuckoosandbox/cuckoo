#!/usr/bin/env python
"""
Checks whether the analysis of samples yields the expected results
from different analysis packages.
"""
import argparse
import json
import logging
import os.path
import subprocess
import sys
import time
import unittest
import SimpleHTTPServer
import SocketServer
import threading

#todo: getaddrinfo e.g. task 72 /  77


CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)
from lib.cuckoo.core.database import Database
from cuckoo import cuckoo_init, cuckoo_main
log = logging.getLogger()


class TestRelease(unittest.TestCase):
    def run_analysis(self, file, package, url=None):
        if url:
            db.add_url(url=url, package="ie", timeout=args.timeout)
        else:
            db.add_path(file_path=file, package=package, timeout=args.timeout)

        try:
            cuckoo_main(max_analysis_count=1)
        except Exception as e:
            print ("Error running analysis..", e)

        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                              "latest", "reports", "report.json")

        report = json.load(open(report_path, "rb")) 

        # verify that a process has been injected at all
        self.assertTrue(report.get("behavior").get("processes") != [], "No injected process found.")
        return report

    # collect and verify loaded DLLs via LdrLoadDLL in report
    def check_loaded_dlls(self, report, dlls):
        dlls_loaded = []
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "system" and c["api"] == "LdrLoadDll":
                    for a in c["arguments"]:
                        if a["name"] == "FileName":
                            dlls_loaded.append(a["value"])
        for d in dlls:                    
            self.assertTrue(d in dlls_loaded, "DLL %s not loaded" %(d))

    # check if files have been created
    def check_files(self, report, files):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "filesystem" and c["api"] == "NtCreateFile":
                    for a in c["arguments"]:
                        if a["name"]=="FileName":
                            try:
                                fname = a["value"].split("\\")
                                files.remove(fname[len(fname)-1:][0])
                            except:
                                pass

        self.assertFalse(files, "Files have note been written: %s" %(files))

    # check for dropped files
    def check_dropped_files(self, report, files):
        for d in report["dropped"]:
            try:
                files.remove(d["name"])
            except:
                pass

        self.assertFalse(files, "Files have note been seen as dropped: %s" %(files))

    # verify dns requests in report
    def check_dns_requests(self, report, hosts):
        host_lookups = []
        addr_infos = []
        for p in report["network"]["dns"]:
            host_lookups.append(p["request"])

        for d in hosts:                    
            self.assertTrue(d in host_lookups, "Host %s not listed in DNS requests" %(d))


    # check for network connections in report
    def check_network(self, report, network_items):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "network":
                    for a in c["arguments"]:
                        try:
                            network_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass
        self.assertFalse(network_items, "Not all network items found. Not found: %s" %(network_items))

    # check for network connections in report
    def check_socket(self, report, socket_items):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "socket":
                    for a in c["arguments"]:
                        try:
                            socket_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass
        self.assertFalse(socket_items, "Not all socket items found. Not found: %s" %(socket_items))

    # check for network connections in report
    def check_http(self, report, urls):
        for h in report["network"]["http"]:
            try: 
                urls.remove(h["uri"])
            except: 
                pass
        self.assertFalse(urls, "Not all URLs found. Not found: %s" %(urls))


    # verify dns requests in report
    def check_registry(self, report, reg_items, reg_keys):
        for p in report["behavior"]["processes"]:
            for c in p.get("calls"):
                if c["category"] == "registry":
                    for a in c["arguments"]:
                        try:
                            reg_items.remove({c["api"]:{a["name"]:a["value"]}})
                        except:
                            pass

        self.assertFalse(reg_items, "Not all registry items found. Not found: %s" %(reg_items))

        # check for complete regkey list
        self.assertTrue(report.get("behavior").get("summary").get("keys"), "No Registry Keys found at all")
        for r in reg_keys:
            self.assertTrue(r in report["behavior"]["summary"]["keys"], "Key not listed: %s" %(r))

    def check_processes(self, report, proc_list): 
        for p in report["behavior"]["processes"]:
            try:
                proc_list.remove(p["process_name"])
            except:
                pass
        self.assertFalse(proc_list, "Not all processes found. Not found: %s" %(proc_list))


    # analysis test for the python analysis package
    def test_python(self):
        report = self.run_analysis(os.path.abspath("test_samples/python.py"), "python")

        # check for loaded dlls
        self.check_loaded_dlls(report, ["kernel32","msvcrt"])

        # check for dns requests
        self.check_dns_requests(report, ["google.com","reddit.com","twitter.com","facebook.com"])

        # check for network items
        self.check_network(report, [{"getaddrinfo":{"NodeName":"google.com"}},{"getaddrinfo":{"NodeName":"reddit.com"}},{"getaddrinfo":{"NodeName":"twitter.com"}}])

        # check for registry entries / changes
        # dict: {"api-value":{"name-value":"value-value"}}
        self.check_registry(report,[ 
                    {u"RegCreateKeyExA":{u"SubKey":u"Software\\Cuckoo\\ReleaseTest"}},
                ], 
                ["HKEY_LOCAL_MACHINE\\Software\\Cuckoo\\ReleaseTest"]
            )

        # check for downloaded executable via http
        self.check_http(report,["http://192.168.56.1:8089/tests/test_samples/dl.exe"])

        # check if file "test.exe" has been created
        self.check_files(report, ["test.exe"])

        # check if file as dropped file
        self.check_dropped_files(report, ["test.exe"])
 
        # check if downloaded executable is detected executed
        self.check_processes(report,["test.exe"])

    # analysis test for the Internet Explorer analysis package
    def test_ie(self):
        # start analysis
        report = self.run_analysis("", "ie", "http://192.168.56.1:8089/tests/test_samples/ie_exploit.html")

        # check for spawned sub processes
        self.check_processes(report,["calc.exe"])

    # analysis test for the exe analysis package
    def test_exe(self):
        self.assertTrue(os.path.isfile("test_samples/dl.exe"), "Test sample \"test_samples/dl.exe\" does not exist. Maybe not compiled dl.c?")

        report = self.run_analysis(os.path.abspath("test_samples/dl.exe"), "exe")

        # check for processes
        self.check_processes(report,["dl.exe"])

        # check for dns requests
        self.check_dns_requests(report, ["facebook.com"])

        # check for network items
        self.check_socket(report, [{"gethostbyname":{"Name":"facebook.com"}}])

        # check for registry entries / changes
        # dict: {"api-value":{"name-value":"value-value"}}
        self.check_registry(report,[ 
                    {u"RegCreateKeyExA":{u"SubKey":u"Software\\Cuckoo\\DL.exe"}},
                ], 
                ["HKEY_LOCAL_MACHINE\\Software\\Cuckoo\\DL.exe"]
            )        


    # analysis test for the pdf analysis package
    # requires Adobe <= 9.x
    def test_pdf(self):
        report = self.run_analysis(os.path.abspath("test_samples/dl_exe.pdf"), "pdf")
        self.check_network(report, [
                {"InternetConnectA":{"ServerName":"192.168.56.1"}}, 
                {"InternetConnectA":{"ServerPort":"8089"}},
                {"HttpOpenRequestA":{"Path":"/tests/test_samples/dl.exe"}}
            ])


    # analysis test for the doc analysis package
    def test_doc(self):
        report = self.run_analysis(os.path.abspath("test_samples/doc.doc"), "doc")
        self.check_network(report, [
                {"InternetConnectA":{"ServerName":"192.168.56.1"}}, 
                {"InternetConnectA":{"ServerPort":"8089"}},
                {"HttpOpenRequestA":{"Path":"/tests/test_samples/dl.exe"}}
            ])



    # analysis test for the xls analysis package
    def test_xls(self):
        self.assertTrue(False, "Not yet implemented")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--packages", type=str, nargs="+", help="Test against specific packages only.")
    parser.add_argument("-v", "--verbosity", type=int, default=0, help="Set test-verbosity.")
    parser.add_argument("-t", "--timeout", type=int, default=50, help="Sets the analysis timeout.")
    parser.add_argument("-c", "--clean", action="store_true", help="Clean storage before tests.")
    args = parser.parse_args()

    # clean db if requested
    if args.clean:
        subprocess.Popen([os.path.join(CUCKOO_ROOT, 'utils', 'clean.sh')],
            cwd=CUCKOO_ROOT).wait()

    # init cuckoo
    cuckoo_init(quiet=True if args.verbosity == 0 else False)
    db = Database()

    
    # start http server serving the exploit
    host_ip = "192.168.56.1"
    host_port = 8089
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", host_port), handler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    # run test suite
    if (args.packages):
        suite = unittest.TestSuite()
        for p in args.packages:
            suite.addTest(TestRelease("test_%s" %(p)))
        runner = unittest.TextTestRunner(verbosity=args.verbosity).run(suite)
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestRelease)    
        unittest.TextTestRunner(verbosity=args.verbosity).run(suite)

    # shutdown http server
    httpd.shutdown()
