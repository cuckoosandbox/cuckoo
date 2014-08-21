#!/usr/bin/env python
"""
Checks whether the analysis of samples yields the expected results
from different analysis packages.
"""
import argparse
import os.path
import subprocess
import sys
import unittest
import SimpleHTTPServer
import SocketServer
import threading
from package_tests.python_tests import TestPythonPackage
from package_tests.exe_tests import TestExePackage
from package_tests.ie_tests import TestIEPackage
from package_tests.pdf_tests import TestPDFPackage
from package_tests.doc_tests import TestDocPackage


CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)
from cuckoo import cuckoo_init

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbosity", type=int, default=0, help="Set test-verbosity.")
    parser.add_argument("-c", "--clean", action="store_true", help="Clean storage before tests.")
    args = parser.parse_args()

    # clean db if requested
    if args.clean:
        subprocess.Popen([os.path.join(CUCKOO_ROOT, 'utils', 'clean.sh')],
            cwd=CUCKOO_ROOT).wait()

    # init cuckoo
    cuckoo_init(quiet=True if args.verbosity == 0 else False)

    
    # start http server serving the exploit
    host_ip = "192.168.56.1"
    host_port = 8089
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", host_port), handler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TestPythonPackage))
    suite.addTests(loader.loadTestsFromTestCase(TestExePackage)) 
    suite.addTests(loader.loadTestsFromTestCase(TestIEPackage)) 
    suite.addTests(loader.loadTestsFromTestCase(TestPDFPackage)) 
    suite.addTests(loader.loadTestsFromTestCase(TestDocPackage)) 
    unittest.TextTestRunner(verbosity=args.verbosity).run(suite)

    # shutdown http server
    httpd.shutdown()
