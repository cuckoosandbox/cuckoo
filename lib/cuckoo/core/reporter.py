# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import inspect
import logging

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.objects import LocalDict
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.plugins import list_plugins

log = logging.getLogger(__name__)

class Reporter:
    """Reporting Engine.

    This class handles the loading and execution of the enabled reporting
    modules. It receives the analysis results dictionary from the Processing
    Engine and pass it over to the reporting modules before executing them.
    """

    def __init__(self, analysis_path, custom=""):
        """@param analysis_path: analysis folder path.
        @param custom: custom options.
        """
        self.analysis_path = analysis_path
        self.custom = custom
        self.cfg = Config(cfg=os.path.join(CUCKOO_ROOT,
                                           "conf",
                                           "reporting.conf"))

    def _run_report(self, module, results):
        """Run a single reporting module.
        @param module: reporting module.
        @param results: results results from analysis.
        """
        # Initialize current reporting module.
        current = module()
        # Give it the path to the analysis results folder.
        current.set_path(self.analysis_path)
        # Load the content of the analysis.conf file.
        current.cfg = Config(current.conf_path)

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        options = self.cfg.get(module_name)

        # If the reporting module is disabled in the config, skip it.
        if not options.enabled:
            return

        # Give it the content of the relevant section from the reporting.conf
        # configuration file.
        current.set_options(options)

        try:
            # Run report, for each report a brand new copy of results is
            # created, to prevent a reporting module to edit global
            # result set and affect other reporting modules.
            current.run(LocalDict(results))
            log.debug("Executed reporting module \"%s\""
                      % current.__class__.__name__)
        except CuckooReportError as e:
            log.warning("The reporting module \"%s\" returned the following "
                        "error: %s" % (current.__class__.__name__, e))
        except Exception as e:
            log.exception("Failed to run the reporting module \"%s\":"
                          % (current.__class__.__name__))

    def run(self, results):
        """Generates all reports.
        @param results: analysis results.
        @raise CuckooReportError: if a report module fails.
        """
        # In every reporting module you can specify a numeric value that
        # represents at which position that module should be executed among
        # all the available ones. It can be used in the case where a
        # module requires another one to be already executed beforehand.
        modules_list = list_plugins(group="reporting")
        modules_list.sort(key=lambda module: module.order)

        # Run every loaded reporting module.
        for module in modules_list:
            self._run_report(module, results)
