# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pkgutil
import inspect
import logging
from collections import defaultdict
from distutils.version import StrictVersion

from lib.cuckoo.common.abstracts import Auxiliary, Machinery, Processing
from lib.cuckoo.common.abstracts import Report, Signature
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

_modules = defaultdict(dict)

def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"], -1)
    except ImportError as e:
        raise CuckooCriticalError("Unable to import plugin "
                                  "\"{0}\": {1}".format(name, e))
    else:
        load_plugins(module)

def import_package(package):
    prefix = package.__name__ + "."
    for loader, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue

        import_plugin(name)

def load_plugins(module):
    for name, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, Auxiliary) and value is not Auxiliary:
                register_plugin("auxiliary", value)
            elif issubclass(value, Machinery) and value is not Machinery:
                register_plugin("machinery", value)
            elif issubclass(value, Processing) and value is not Processing:
                register_plugin("processing", value)
            elif issubclass(value, Report) and value is not Report:
                register_plugin("reporting", value)
            elif issubclass(value, Signature) and value is not Signature:
                register_plugin("signatures", value)

def register_plugin(group, name):
    global _modules
    group = _modules.setdefault(group, [])
    group.append(name)

def list_plugins(group=None):
    if group:
        return _modules[group]
    else:
        return _modules

class RunAuxiliary(object):
    """Auxiliary modules manager."""

    def __init__(self, task, machine):
        self.task = task
        self.machine = machine
        self.cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf"))
        self.enabled = []

    def start(self):
        auxiliary_list = list_plugins(group="auxiliary")
        if auxiliary_list:
            for module in auxiliary_list:
                try:
                    current = module()
                except:
                    log.exception("Failed to load the auxiliary module "
                                  "\"{0}\":".format(module))
                    return

                module_name = inspect.getmodule(current).__name__
                if "." in module_name:
                    module_name = module_name.rsplit(".", 1)[1]

                try:
                    options = self.cfg.get(module_name)
                except CuckooOperationalError:
                    log.debug("Auxiliary module %s not found in "
                              "configuration file", module_name)
                    continue

                if not options.enabled:
                    continue

                current.set_task(self.task)
                current.set_machine(self.machine)
                current.set_options(options)

                try:
                    current.start()
                except NotImplementedError:
                    pass
                #except Exception as e:
                #    log.warning("Unable to start auxiliary module %s: %s",
                #                module_name, e)
                else:
                    log.debug("Stopped auxiliary module: %s", module_name)
                    self.enabled.append(current)

    def stop(self):
        for module in self.enabled:
            try:
                module.stop()
            except NotImplementedError:
                pass
            except Exception as e:
                log.warning("Unable to stop auxiliary module: %s", e)
            else:
                log.debug("Stopped auxiliary module: %s", module)

class RunProcessing(object):
    """Analysis Results Processing Engine.

    This class handles the loading and execution of the processing modules.
    It executes the enabled ones sequentially and generates a dictionary which
    is then passed over the reporting engine.
    """

    def __init__(self, task_id):
        """@param task_id: ID of the analyses to process."""
        self.task = Database().view_task(task_id).to_dict()
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        self.cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "processing.conf"))

    def process(self, module):
        """Run a processing module.
        @param module: processing module to run.
        @param results: results dict.
        @return: results generated by module.
        """
        # Initialize the specified processing module.
        try:
            current = module()
        except:
            log.exception("Failed to load the processing module "
                          "\"{0}\":".format(module))
            return

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.debug("Processing module %s not found in configuration file",
                      module_name)
            return None

        # If the processing module is disabled in the config, skip it.
        if not options.enabled:
            return None

        # Give it path to the analysis results.
        current.set_path(self.analysis_path)
        # Give it the analysis task object.
        current.set_task(self.task)
        # Give it the options from the relevant processing.conf section.
        current.set_options(options)

        try:
            # Run the processing module and retrieve the generated data to be
            # appended to the general results container.
            data = current.run()

            log.debug("Executed processing module \"%s\" on analysis at "
                      "\"%s\"", current.__class__.__name__, self.analysis_path)

            # If succeeded, return they module's key name and the data to be
            # appended to it.
            return {current.key: data}
        except CuckooDependencyError as e:
            log.warning("The processing module \"%s\" has missing dependencies: %s", current.__class__.__name__, e)
        except CuckooProcessingError as e:
            log.warning("The processing module \"%s\" returned the following "
                        "error: %s", current.__class__.__name__, e)
        except:
            log.exception("Failed to run the processing module \"%s\":",
                          current.__class__.__name__)

        return None

    def run(self):
        """Run all processing modules and all signatures.
        @return: processing results.
        """
        # This is the results container. It's what will be used by all the
        # reporting modules to make it consumable by humans and machines.
        # It will contain all the results generated by every processing
        # module available. Its structure can be observed through the JSON
        # dump in the analysis' reports folder. (If jsondump is enabled.)
        # We friendly call this "fat dict".
        results = {}

        # Order modules using the user-defined sequence number.
        # If none is specified for the modules, they are selected in
        # alphabetical order.
        processing_list = list_plugins(group="processing")

        # If no modules are loaded, return an empty dictionary.
        if processing_list:
            processing_list.sort(key=lambda module: module.order)

            # Run every loaded processing module.
            for module in processing_list:
                result = self.process(module)
                # If it provided some results, append it to the big results
                # container.
                if result:
                    results.update(result)
        else:
            log.info("No processing modules loaded")

        # Return the fat dict.
        return results

class RunSignatures(object):
    """Run Signatures."""

    def __init__(self, results):
        self.results = results

    def _check_signature_version(self, current):
        """Check signature version.
        @param current: signature class/instance to check.
        @return: check result.
        """
        # Since signatures can hardcode some values or checks that might
        # become obsolete in future versions or that might already be obsolete,
        # I need to match its requirements with the running version of Cuckoo.
        version = CUCKOO_VERSION.split("-")[0]

        # If provided, check the minimum working Cuckoo version for this
        # signature.
        if current.minimum:
            try:
                # If the running Cuckoo is older than the required minimum
                # version, skip this signature.
                if StrictVersion(version) < StrictVersion(current.minimum.split("-")[0]):
                    log.debug("You are running an older incompatible version "
                              "of Cuckoo, the signature \"%s\" requires "
                              "minimum version %s",
                              current.name, current.minimum)
                    return None
            except ValueError:
                log.debug("Wrong minor version number in signature %s",
                          current.name)
                return None

        # If provided, check the maximum working Cuckoo version for this
        # signature.
        if current.maximum:
            try:
                # If the running Cuckoo is newer than the required maximum
                # version, skip this signature.
                if StrictVersion(version) > StrictVersion(current.maximum.split("-")[0]):
                    log.debug("You are running a newer incompatible version "
                              "of Cuckoo, the signature \"%s\" requires "
                              "maximum version %s",
                              current.name, current.maximum)
                    return None
            except ValueError:
                log.debug("Wrong major version number in signature %s",
                          current.name)
                return None

        return True

    def process(self, signature):
        """Run a signature.
        @param signature: signature to run.
        @param signs: signature results dict.
        @return: matched signature.
        """
        # Initialize the current signature.
        try:
            current = signature(self.results)
        except:
            log.exception("Failed to load signature "
                          "\"{0}\":".format(signature))
            return

        log.debug("Running signature \"%s\"", current.name)

        # If the signature is disabled, skip it.
        if not current.enabled:
            return None

        if not self._check_signature_version(current):
            return None

        try:
            # Run the signature and if it gets matched, extract key information
            # from it and append it to the results container.
            if current.run():
                log.debug("Analysis matched signature \"%s\"", current.name)

                # Return information on the matched signature.
                return current.as_result()
        except NotImplementedError:
            return None
        except:
            log.exception("Failed to run signature \"%s\":", current.name)

        return None

    def run(self):
        # This will contain all the matched signatures.
        matched = []

        complete_list = list_plugins(group="signatures")
        evented_list = [sig(self.results)
                        for sig in complete_list
                        if sig.enabled and sig.evented and
                        self._check_signature_version(sig)]

        if evented_list:
            log.debug("Running %u evented signatures", len(evented_list))
            for sig in evented_list:
                if sig == evented_list[-1]:
                    log.debug("\t `-- %s", sig.name)
                else:
                    log.debug("\t |-- %s", sig.name)

            # Iterate calls and tell interested signatures about them
            for proc in self.results["behavior"]["processes"]:
                for call in proc["calls"]:
                    # Loop through active evented signatures.
                    for sig in evented_list:
                        # Skip current call if it doesn't match the filters (if any).
                        if sig.filter_processnames and not proc["process_name"] in sig.filter_processnames:
                            continue
                        if sig.filter_apinames and not call["api"] in sig.filter_apinames:
                            continue
                        if sig.filter_categories and not call["category"] in sig.filter_categories:
                            continue

                        result = None
                        try:
                            result = sig.on_call(call, proc)
                        except NotImplementedError:
                            result = False
                        except:
                            log.exception("Failed to run signature \"%s\":", sig.name)
                            result = False

                        # If the signature returns None we can carry on, the
                        # condition was not matched.
                        if result is None:
                            continue

                        # On True, the signature is matched.
                        if result is True:
                            log.debug("Analysis matched signature \"%s\"", sig.name)
                            matched.append(sig.as_result())
                            if sig in complete_list:
                                complete_list.remove(sig)
                        
                        # Either True or False, we don't need to check this sig anymore.
                        evented_list.remove(sig)
                        del sig

            # Call the stop method on all remaining instances.
            for sig in evented_list:
                try:
                    result = sig.on_complete()
                except NotImplementedError:
                    continue
                except:
                    log.exception("Failed run on_complete() method for signature \"%s\":", sig.name)
                    continue
                else:
                    if result is True:
                        log.debug("Analysis matched signature \"%s\"", sig.name)
                        matched.append(sig.as_result())
                        if sig in complete_list:
                            complete_list.remove(sig)

        # Compat loop for old-style (non evented) signatures.
        if complete_list:
            log.debug("Running non-evented signatures")

            for signature in complete_list:
                match = self.process(signature)
                # If the signature is matched, add it to the list.
                if match:
                    matched.append(match)

                # Reset the ParseProcessLog instances after each signature
                if "behavior" in self.results:
                    for process in self.results["behavior"]["processes"]:
                        process["calls"].reset()

        if matched:
            # Sort the matched signatures by their severity level.
            matched.sort(key=lambda key: key["severity"])

        self.results["signatures"] = matched

class RunReporting:
    """Reporting Engine.

    This class handles the loading and execution of the enabled reporting
    modules. It receives the analysis results dictionary from the Processing
    Engine and pass it over to the reporting modules before executing them.
    """

    def __init__(self, task_id, results):
        """@param analysis_path: analysis folder path."""
        self.task = Database().view_task(task_id).to_dict()
        self.results = results
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        self.cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "reporting.conf"))

    def process(self, module):
        """Run a single reporting module.
        @param module: reporting module.
        @param results: results results from analysis.
        """
        # Initialize current reporting module.
        try:
            current = module()
        except:
            log.exception("Failed to load the reporting module \"{0}\":".format(module))
            return

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.debug("Reporting module %s not found in configuration file", module_name)
            return

        # If the reporting module is disabled in the config, skip it.
        if not options.enabled:
            return

        # Give it the path to the analysis results folder.
        current.set_path(self.analysis_path)
        # Give it the analysis task object.
        current.set_task(self.task)
        # Give it the the relevant reporting.conf section.
        current.set_options(options)
        # Load the content of the analysis.conf file.
        current.cfg = Config(current.conf_path)

        try:
            current.run(self.results)
            log.debug("Executed reporting module \"%s\"", current.__class__.__name__)
        except CuckooDependencyError as e:
            log.warning("The reporting module \"%s\" has missing dependencies: %s", current.__class__.__name__, e)
        except CuckooReportError as e:
            log.warning("The reporting module \"%s\" returned the following error: %s", current.__class__.__name__, e)
        except:
            log.exception("Failed to run the reporting module \"%s\":", current.__class__.__name__)

    def run(self):
        """Generates all reports.
        @raise CuckooReportError: if a report module fails.
        """
        # In every reporting module you can specify a numeric value that
        # represents at which position that module should be executed among
        # all the available ones. It can be used in the case where a
        # module requires another one to be already executed beforehand.
        reporting_list = list_plugins(group="reporting")

        # Return if no reporting modules are loaded.
        if reporting_list:
            reporting_list.sort(key=lambda module: module.order)

            # Run every loaded reporting module.
            for module in reporting_list:
                self.process(module)
        else:
            log.info("No reporting modules loaded")
