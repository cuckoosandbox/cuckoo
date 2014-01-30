# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import logging
import time
import argparse

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.resultserver import Resultserver

class Machine():
    def __init__(self, ip):
        self.ip = ip

class Task():
    def __init__(self, tid):
        self.id = tid

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Standalone resultserver for testing purpose')
    parser.add_argument('id', type=int, help='Job ID to use')
    parser.add_argument('machine_ip', type=str, help='IP address of analysis machine')

    args = parser.parse_args()

    log = logging.getLogger()
    FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    logging.basicConfig(format=FORMAT)
    log.setLevel(logging.DEBUG)

    t = Task(args.id)
    m = Machine(args.machine_ip)
    r = Resultserver()
    Resultserver().add_task(t, m)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    Resultserver().del_task(t, m)
