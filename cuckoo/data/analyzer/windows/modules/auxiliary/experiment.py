# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import json
import logging
import os.path


from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


class Experiment(Auxiliary):
    """Prepares the environment to try and keep track of processes
    that may have been created from dropped files created during the previous
    task in this experiment"""

    def init(self):
        self.handlers = {
            "injectables": self._handle_injectables
        }
        self.experiment_info = {}

    def start(self):
        if self.analyzer.config.package != "experiment":
            return

        exp_info = os.path.join(self.analyzer.path, "experiment.json")
        if not os.path.exists(exp_info):
            log.debug("Experiment.json file not found in analyzer path")
            return

        with open(exp_info, "rb") as fp:
            self.experiment_info = json.loads(fp.read())

            for key in self.experiment_info:
                handler = self.handlers.get(key)
                if handler:
                    handler()

    def _GetlongPathNameW(self, shortpath, bufsize=None):
        """"Uses GetLongPathNameW to get the real path for 8.3 filenames/paths
        https://en.wikipedia.org/wiki/8.3_filename"""
        if not bufsize:
            bufsize = len(shortpath) * 2

        buf = ctypes.create_unicode_buffer(bufsize)
        GetLongPathNameW = ctypes.windll.kernel32.GetLongPathNameW

        if not GetLongPathNameW:
            return shortpath

        len_needed = GetLongPathNameW(unicode(shortpath), buf, bufsize)
        if len_needed > bufsize:
            log.debug("Path too long for buffer size. Recursively calling with"
                      " required size")
            self._GetlongPathNameW(shortpath, bufsize=len_needed)
        elif len_needed == 0:
            return shortpath
        else:
            return buf.value

    def _handle_injectables(self):
        """Reads file paths and adds them to the experiment
        infomation dict in the analyzer"""

        if len(self.experiment_info["injectables"]) < 1:
            return

        injectables = self.experiment_info["injectables"]
        unique_paths = []
        for filepath in injectables:
            # Check if tilde in path to determine if path is possibly 8.3 path
            if "~" in filepath:
                filepath = self._GetlongPathNameW(filepath)

            if filepath not in unique_paths:
                unique_paths.append(filepath)

        log.debug("Added paths to possible injectables to experiment data in"
                  " analyzer")
        self.analyzer.experiment.update({
            "injectables": unique_paths
        })
