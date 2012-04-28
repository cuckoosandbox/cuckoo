#!/usr/bin/env python
from lib.cuckoo.common.logo import logo
from lib.cuckoo.core.startup import check_dependencies, create_structure
from lib.cuckoo.core.scheduler import Scheduler

def main():
    logo()
    check_dependencies()
    create_structure()

    try:
        sched = Scheduler()
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        print e
