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

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.database import Database
from cuckoo import cuckoo_init, cuckoo_main

log = logging.getLogger()

def run_analysis(src):
    _, path = tempfile.mkstemp(suffix='.py')
    open(path, 'wb').write(src)
    db.add_path(file_path=path, package='python', timeout=30)

    try:
        cuckoo_main(max_analysis_count=1)
    except Exception as e:
        print 'Error running analysis..', e

    report = os.path.join(CUCKOO_ROOT, 'storage', 'analyses',
                          'latest', 'reports', 'report.json')
    return json.load(open(report, 'rb'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # parser.add_argument("vmname", type=str, required=False, help="Name of the Virtual Machine to check.")
    args = parser.parse_args()

    # Clean the database.
    subprocess.Popen([os.path.join(CUCKOO_ROOT, 'utils', 'clean.sh')],
                     cwd=CUCKOO_ROOT).wait()

    cuckoo_init()

    db = Database()

    report = run_analysis("import time; print 'hello!!1'; time.sleep(3)")
    assert 'behavior' in report
    assert 'processes' in report['behavior']
    assert len(report['behavior']['processes']) == 1

    buf = ''
    for row in report['behavior']['processes'][0]['calls']:
        if row['api'] != 'WriteConsoleA':
            continue

        args = dict((arg['name'], arg['value']) for arg in row['arguments'])
        buf += args['Buffer']

    assert buf == 'hello!!1\r\n'
    log.info('Passed first test!')

    report = run_analysis("open('a.txt', 'wb').write('Hello World')")
    assert 'dropped' in report
    assert len(report['dropped']) == 1
    assert open(report['dropped'][0]['path']).read() == 'Hello World'

    log.info('Passed second test!')
