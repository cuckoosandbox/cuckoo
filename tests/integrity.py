#!/usr/bin/env python
"""
Checks the integrity of one or more virtual machine(s). In order to ensure
that there are no remaining tasks in the queue this utility will clean the
entire database before starting various analyses.
"""
import argparse
import json
import logging
import os.path
import subprocess
import sys
import tempfile
import unittest

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.database import Database
from cuckoo import cuckoo_init, cuckoo_main

log = logging.getLogger()


class TestIntegrity(unittest.TestCase):
    def run_analysis(self, src):
        _, path = tempfile.mkstemp(suffix='.py')
        # A simple if statement to fix indentation errors.
        open(path, 'wb').write('if True:\n' + src)
        db.add_path(file_path=path, package='python', timeout=30)

        try:
            cuckoo_main(max_analysis_count=1)
        except Exception as e:
            print 'Error running analysis..', e

        report = os.path.join(CUCKOO_ROOT, 'storage', 'analyses',
                              'latest', 'reports', 'report.json')
        return json.load(open(report, 'rb'))

    def test_hello_world(self):
        report = self.run_analysis("""
            import time
            print 'hello!!1'
            time.sleep(3)
        """)
        self.assertTrue('behavior' in report)
        self.assertTrue('processes' in report['behavior'])
        self.assertEqual(len(report['behavior']['processes']), 1)

        buf = ''
        for row in report['behavior']['processes'][0]['calls']:
            if row['api'] != 'WriteConsoleA':
                continue

            args = dict((arg['name'], arg['value']) for arg in row['arguments'])
            buf += args['Buffer']

        self.assertEqual(buf, 'hello!!1\r\n')

    def test_file_write(self):
        report = self.run_analysis("""
            open('a.txt', 'wb').write('Hello World')
        """)
        self.assertTrue('dropped' in report)
        self.assertEqual(len(report['dropped']), 1)
        self.assertEqual(open(report['dropped'][0]['path']).read(),
                         'Hello World')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # parser.add_argument("vmname", type=str, required=False, help="Name of the Virtual Machine to check.")
    args = parser.parse_args()

    # Clean the database.
    subprocess.Popen([os.path.join(CUCKOO_ROOT, 'utils', 'clean.sh')],
                     cwd=CUCKOO_ROOT).wait()

    cuckoo_init(quiet=True)

    db = Database()

    unittest.main()
