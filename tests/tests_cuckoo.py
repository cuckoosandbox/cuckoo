#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import re
import json
from os import path, symlink, listdir
import unittest
import subprocess

TESTS_DIR = path.dirname(path.abspath(__file__))
ANALYZER_ROOT = path.dirname(TESTS_DIR)

def cuckoo_root():
    """ It's ../../cuckoo """
    # ./
    return path.join(path.dirname(ANALYZER_ROOT), "cuckoo")


def submit_job(target, options):
    # Force using OS X machines for running targets
    options.update({"platform" : "darwin"})
    # Too lazy to re-implement this stuff myself, so use an existing tool
    submit_py = path.join(cuckoo_root(), "utils", "submit.py")
    cmd = ["python", submit_py]
    # Transform options into --options. I tried to implement a flatMap() here
    cmd += sum(map(lambda (x, y): ["--"+x, y], options.items()), [])
    cmd += [target]
    subprocess.check_call(cmd)

def latest_analysis_results():
    storage_dir = path.realpath(path.join(cuckoo_root(), "storage", "analyses", "latest"))
    with open(path.join(storage_dir, "reports", "report.json"), "r") as report_file:
        report = json.load(report_file)
    return {
        "report": report,
        "files" : listdir(path.join(storage_dir, "files")),
        "logs"  : listdir(path.join(storage_dir, "logs")),
        "analysis_log" : path.join(storage_dir, "analysis.log")
    }

def cuckoo_analysis(target, options):
    """ Returns a dictionary with the following keys:
    :report       => dictionary contents of report.json,
    :files        => list of dropped files (full local paths),
    :logs         => list of log files (full local paths),
    :analysis_log => analysis.log full path
    """
    # Add new analysis job to the Cuckoo database
    submit_job(target, options)
    # then try to read it's output and get analysis results from there
    def read_cuckoo_output():
        return CuckooTests.cuckoo.stderr.readline().rstrip()
    def is_completion(line):
        return None != re.search(r'.*Task #[0-9]{3}: analysis .* completed', line)
    def is_error(line):
        # Nah, don't even care about returning anything on error
        if re.search(r'.*ERROR: Analysis failed:', line) != None:
            raise Exception("Cuckoo analysis failed")

    line = read_cuckoo_output()
    while (not is_completion(line)) and (not is_error(line)):
        line = read_cuckoo_output()
    # Now go to the results directory and parse all the data
    return latest_analysis_results()

# TODO(rodionovd):
# 1) build assets from sources or store precompiled programms? Bear in mind that
# user shall be able to run these tests on any host...


@unittest.skipUnless(path.exists(cuckoo_root()), "Unable to locate Cuckoo")
class CuckooTests(unittest.TestCase):

    cuckoo = None

    @classmethod
    def setUpClass(cls):
        # Symlink the darwin analyzer into Cuckoo's analyzer directory
        source = path.join(ANALYZER_ROOT, "analyzer", "darwin")
        destination = path.join(cuckoo_root(), "analyzer", "darwin")
        # setUpClass() is called even when @unittest.skipUnless skips
        # all the tests, so we verify it again...
        if path.exists(cuckoo_root()):
            if not path.exists(destination):
                symlink(source, destination)
            # Initialize Cuckoo Host
            cls.launch_cuckoo()

    @classmethod
    def tearDownClass(cls):
        if path.exists(cuckoo_root()):
            cls.terminate_cuckoo()

    def current_target(self):
        return path.join(TESTS_DIR, "assets", self._testMethodName)

    #-#-#-#-#-#-#-# #-#-#-#-#-#-#-# #-#-#-#-#-#-#-#
    # Cuckoo management
    #-#-#-#-#-#-#-# #-#-#-#-#-#-#-# #-#-#-#-#-#-#-#

    @classmethod
    def launch_cuckoo(cls):
        # Let's hope Python *is* in PATH
        cmd = ["python", path.join(cuckoo_root(), "cuckoo.py")]
        cls.cuckoo = subprocess.Popen(cmd, stderr=subprocess.PIPE)
        # Now see if it launched successfully.
        # Basically, what we do here is reading Cuckoo's output until we hit the
        # success message *OR* the whole thing is terminated due to an error
        isalive = (lambda x: x.poll() == None)
        while isalive(cls.cuckoo):
            if "Waiting for analysis tasks" in cls.cuckoo.stderr.readline().rstrip():
                break
        # so if Cuckoo is dead at this moment, something bad has happend
        if not isalive(cls.cuckoo):
            raise Exception("Cuckoo failed to launch")

    @classmethod
    def terminate_cuckoo(cls):
        try:
            cls.cuckoo.terminate()
        except OSError as _:
            pass # it's likely to be already terminated

    #-#-#-#-#-#-#-# #-#-#-#-#-#-#-# #-#-#-#-#-#-#-#
    # Test cases
    #-#-#-#-#-#-#-# #-#-#-#-#-#-#-# #-#-#-#-#-#-#-#

    def test_cuckoo_blah(self):
        # given
        target = "/Backup/Cuckoo Research/fopen_demo"
        options = {
        }
        # when
        results = cuckoo_analysis(target, options)
        # then
        self.assertTrue(len(results["logs"]) > 0)

    def test_foo(self):
        self.assertEqual(cuckoo_root(), "/Users/rodionovd/projects/cuckoo")
