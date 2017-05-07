# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import time
import shutil
import logging
import Queue
import multiprocessing
import modules.processing
import modules.signatures
import modules.reporting


from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import create_folder
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.plugins import list_plugins, import_package, RunAuxiliary, RunProcessing
from lib.cuckoo.core.plugins import RunSignatures, RunReporting
from lib.cuckoo.core.resultserver import Resultserver

log = logging.getLogger(__name__)

def process_results(task,cfg):
        """Process the analysis results and generate the enabled reports."""
        log.info("Process results for %s \"%s\" (task=%d)", task.category.upper(), task.target, task.id)
        # code to initialize required modules
        try:
            # Import all processing modules.
            import_package(modules.processing)
            # Import all signatures.
            import_package(modules.signatures)
            # Import all reporting modules.
            import_package(modules.reporting)
        except Exception as e:
            log.info("Exception in loading modules %s ", str(e))
        # end code to initialize modules
        results = RunProcessing(task_id=task.id).run()
        start = time.time()
        RunSignatures(results=results).run()
        delta = time.time() - start
        report_len = len(str(results))
        log.info('Signature Processing for task %s with report length %s took %s seconds. %s KB/sec' % (task.id,report_len,delta,report_len/(delta*1024.0)))
        RunReporting(task_id=task.id, results=results).run()

        # If the target is a file and the user enabled the option,
        # delete the original copy.
        if task.category == "file" and cfg.cuckoo.delete_original:
            if not os.path.exists(task.target):
                log.warning("Original file does not exist anymore: \"%s\": "
                            "File not found", task.target)
            else:
                try:
                    os.remove(task.target)
                except OSError as e:
                    log.error("Unable to delete original file at path "
                              "\"%s\": %s", task.target, e)

        # If the target is a file and the user enabled the delete copy of
        # the binary option, then delete the copy.
        if task.category == "file" and cfg.cuckoo.delete_bin_copy:
            if not os.path.exists(binary):
                log.warning("Copy of the original file does not exist anymore: \"%s\": File not found", binary)

        Database().set_status(task.id, TASK_REPORTED)
        log.info("Processing complete for %s \"%s\" (task=%d)", task.category.upper(), task.target, task.id)


class Multianalysis:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self):
        self.running = True
        self.cfg = Config()
        self.db = Database()

    def stop(self):
        self.running = False


    def start(self):
        """Start scheduler."""

        log.info("Waiting for analysis tasks...")
        jobs = {}


        # This loop runs forever.
        while self.running:

            tasks = self.db.list_tasks(status=TASK_COMPLETED) 
            
            if tasks:
                for task in tasks:
                    if not jobs.has_key(task.id):
                        p = multiprocessing.Process(target=process_results, args=(task,self.cfg))
                        jobs[task.id] = p
                        p.start()

            time.sleep(10)
            for key, value in jobs.items():
                if not value.is_alive():
                    value.join()
                    del jobs[key]
           

