# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import threading
import time
import subprocess

from lib.api.process import Process, subprocess_checkoutput
from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class Experiment(Package):
    """Experiment analysis package."""

    def start(self, target):
        if self.analyzer.config.package != "experiment":
            return

        if self.analyzer.config.options.get("free"):
            log.debug("The 'free' option was used, not tracking processes")
            return

        self.injectables = self.analyzer.experiment.get("injectables")
        if not self.injectables:
            log.debug("No injectable paths in experiment data in analyzer")
            return

        self.run = True
        threading.Thread(target=self._run).start()

    def _try_inject(self, pid):
        p = Process(pid=pid)
        if p.inject(track=True):
            self.pids.append(pid)
            log.debug("Injected into process with pid: %s", pid)

    def _get_pid_file_dict(self):
        """Returns a dict of pids and the files used to create
        the corresponding process"""

        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        command = "wmic process get ExecutablePath,processid /format:csv"
        results = subprocess_checkoutput(command, startupinfo=si)

        file_pid = {}
        if not results:
            return file_pid

        for result in results.split("\r\r\n"):
            proc = result.split(",", 2)

            # Check if sufficient entries and not CSV header
            if len(proc) < 3 or proc[0] == "Node":
                continue

            node, exepath, pid = proc

            if exepath == "" or pid == "":
                continue

            file_pid[exepath.lower()] = pid

        return file_pid

    def _run(self):
        """Searches the files used to create all currently running processes
        for files that were dropped during previous experiment analyses.
        Tries to inject if such a process is found"""

        while self.run:
            file_pid = self._get_pid_file_dict()
            if len(file_pid) < 1:
                continue

            for injectable in self.injectables:
                file_path = injectable.lower()

                if file_path in file_pid:
                    pid = int(file_pid[file_path])

                    if pid in self.pids:
                        continue

                    log.debug("Found process for one of the tracked files: %s",
                              file_path)
                    self._try_inject(pid)

            time.sleep(1)
    
    def finish(self):
        self.run = False
        super(Experiment, self).finish()
