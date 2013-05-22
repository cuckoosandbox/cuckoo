# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import inspect
from distutils.version import StrictVersion

from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.plugins import list_plugins

log = logging.getLogger(__name__)

class NetworkAnalyzer:
    """Network analyzer.

    This class handles the loading and execution of the modules collecting
    and analyzing network traffic (tcpdump, etc).
    The enabled modules are executed sequentially before the analysis starts,
    and stopped when the analysis finishes.
    """

    def __init__(self, task, machine):
        """@param task_id: ID of the analyses to process."""
        self.task = task
        self.machine = machine
        self.analysis_path = os.path.join(CUCKOO_ROOT,
                                          "storage",
                                          "analyses",
                                          str(task.id))
        self.cfg = Config(cfg=os.path.join(CUCKOO_ROOT,
                                           "conf",
                                           "networkanalyzer.conf"))
        self.active = []

    def _start_module(self, module):
        """Run a network analysis module.
        @param module: network analysis module to run.
        @return: status True/False.
        """
        # Initialize the specified network analysis module.
        current = module()
        
        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        log.debug("Trying to start network analysis module %s", current.__class__.__name__)

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.debug("Network analysis module %s not found in "
                      "configuration file", module_name)
            return False

        # If the network analysis module is disabled either in the config or in the module itself, skip it.
        if not options.enabled or not current.enabled:
            log.debug("Network analysis module %s is disabled", current.__class__.__name__)
            return False

        # Give it path to the analysis results.
        current.set_path(self.analysis_path)
        # Give it the task object.
        current.set_task(self.task)
        # Give it the virtual machine object.
        current.set_machine(self.machine)
        # Give it the options from the relevant networkanalyzer.conf section.
        current.set_options(options)

        try:
            # Run the network analysis module
            result = current.start()

            log.debug("Executed network analysis module \"%s\" on analysis at \"%s\"",
                      current.__class__.__name__, self.analysis_path)
            
            
            if result:
                self.active.append(current)
            
            return result
        except CuckooProcessingError as e:
            log.warning("The processing module \"%s\" returned the following "
                        "error: %s", current.__class__.__name__, e)
        except Exception as e:
            log.exception("Failed to run the processing module \"%s\":",
                          current.__class__.__name__)

        return False

    def start(self):
        """start all network analysis modules.
        @return: status.
        """

        # Order modules using the user-defined sequence number.
        # If none is specified for the modules, they are selected in
        # alphabetical order.
        modules_list = list_plugins(group="networking")

        # If no modules are loaded, return False.
        if not modules_list:
            log.debug("No network analysis modules loaded")
            return False

        modules_list.sort(key=lambda module: module.order)

        # Run every loaded processing module.
        for module in modules_list:
            result = self._start_module(module)

        return True

    def stop(self):
        """stop all the active network analysis modules
        @return: status
        """
        for module in self.active:
            if module:
                try:
                    module.stop()
                    log.debug("Stopped network analysis module \"%s\" on analysis at \"%s\"",
                              module.__class__.__name__, self.analysis_path)
                except Exception as e:
                    log.debug("Error stopping network analysis module \"%s\" on analysis at \"%s\": %s",
                              module.__class__.__name__, self.analysis_path, e)
                finally:
                    self.active.remove(module)
            else:
                log.debug("Network analysis module \"%s\" on analysis at \"%s\" was already stopped",
                          module.__class__.__name__, self.analysis_path)
        
        return True