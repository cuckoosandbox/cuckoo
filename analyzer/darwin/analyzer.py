#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import sys
import logging
import xmlrpclib

from datetime import datetime
from pkgutil import iter_modules
from traceback import format_exc
from lib.common.config import Config
from lib.common.results import NetlogHandler
from lib.core.constants import PATHS
from lib.core.packages import choose_package_class, Package

from lib.core.osx import set_wallclock
from lib.core.host import CuckooHost

class Macalyzer:
    """Cuckoo OS X analyser.
    """

    log = logging.getLogger()

    def __init__(self, host, configuration=None):
        self.config = configuration
        self.host = host

    def _bootstrap(self):
        self._create_result_folders()
        self._setup_logging()
        self._detect_target()

    def run(self):
        """Run analysis.
        """
        self._bootstrap()

        self.log.debug("Starting analyzer from %s", os.getcwd())
        self.log.debug("Storing results at: %s", PATHS["root"])

        package = self._setup_analysis_package()

        if self.config.clock:
            set_wallclock(self.config.clock)
        self._analysis(package)

        return self._complete()

    def _complete(self):
        return True

    #
    # Implementation details
    #

    def _create_result_folders(self):
        for name, folder in PATHS.items():
            if os.path.exists(folder):
                continue
            try:
                os.makedirs(folder)
            except OSError:
                pass

    def _setup_logging(self):
        """ Initialize logger. """
        logger = logging.getLogger()
        formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        nh = NetlogHandler()
        nh.setFormatter(formatter)
        logger.addHandler(nh)
        logger.setLevel(logging.DEBUG)

    def _detect_target(self):
        if self.config.category == "file":
            self.target = os.path.join("/tmp/", str(self.config.file_name))
        else: # It's not a file, but a URL
            self.target = self.config.target

    def _setup_analysis_package(self):
        # Do we have a suggestion about an analysis package?
        if self.config.package:
            suggestion = self.config.package
        elif self.config.category != "file":
            suggestion = "url"
        else:
            suggestion = None
        # Try to figure out what analysis package to use with this target
        kwargs = { "suggestion" : suggestion }
        package_class = choose_package_class(self.config.file_type,
                                             self.config.file_name, **kwargs)
        # Package initialization
        kwargs = {
            "options" : self.config.get_options(),
            "timeout" : self.config.timeout
        }
        return package_class(self.target, self.host, **kwargs)

    def _analysis(self, package):
        package.start()



if __name__ == "__main__":
    success = False
    error = ""

    try:
        config = Config(cfg="analysis.conf")
        host = CuckooHost(config.ip, config.port)
        success = Macalyzer(host, config).run()

    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    except Exception as e:
        error_exc = format_exc()
        error = str(e)
        if len(analyzer.log.handlers):
            analyzer.log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = xmlrpclib.Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["root"])
