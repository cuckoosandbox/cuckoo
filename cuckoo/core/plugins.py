# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import importlib
import inspect
import logging

import cuckoo

from cuckoo.common.config import Config
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.exceptions import CuckooReportError
from cuckoo.common.exceptions import CuckooDependencyError
from cuckoo.common.exceptions import CuckooDisableModule
from cuckoo.common.abstracts import Signature
from cuckoo.common.utils import supported_version
from cuckoo.misc import cwd, version

log = logging.getLogger(__name__)

def enumerate_plugins(dirpath, module_prefix, namespace, class_,
                      attributes={}, as_dict=False):
    """Import plugins of type `class` located at `dirpath` into the
    `namespace` that starts with `module_prefix`. If `dirpath` represents a
    filepath then it is converted into its containing directory. The
    `attributes` dictionary allows one to set extra fields for all imported
    plugins. Using `as_dict` a dictionary based on the module name is
    returned."""
    if os.path.isfile(dirpath):
        dirpath = os.path.dirname(dirpath)

    for fname in os.listdir(dirpath):
        if fname.endswith(".py") and not fname.startswith("__init__"):
            module_name, _ = os.path.splitext(fname)
            importlib.import_module("%s.%s" % (module_prefix, module_name))

    subclasses = class_.__subclasses__()[:]

    plugins = []
    while subclasses:
        subclass = subclasses.pop(0)

        # Include subclasses of this subclass (there are some subclasses, e.g.,
        # LibVirtMachinery, that fail the fail the following module namespace
        # check and as such we perform this logic here).
        subclasses.extend(subclass.__subclasses__())

        # Check whether this subclass belongs to the module namespace that
        # we're currently importing. It should be noted that parent and child
        # namespaces should fail the following if-statement.
        if module_prefix != ".".join(subclass.__module__.split(".")[:-1]):
            continue

        namespace[subclass.__name__] = subclass
        for key, value in attributes.items():
            setattr(subclass, key, value)

        plugins.append(subclass)

    if as_dict:
        ret = {}
        for plugin in plugins:
            ret[plugin.__module__.split(".")[-1]] = plugin
        return ret

    return plugins

class RunAuxiliary(object):
    """Auxiliary modules manager."""

    def __init__(self, task, machine, guest_manager):
        self.task = task
        self.machine = machine
        self.guest_manager = guest_manager

        self.cfg = Config("auxiliary")
        self.enabled = []

    def start(self):
        for module in cuckoo.auxiliary.plugins:
            try:
                current = module()
            except:
                log.exception(
                    "Failed to load the auxiliary module: %s",
                    module, extra={"task_id": self.task["id"]}
                )
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
            current.set_guest_manager(self.guest_manager)
            current.set_options(options)

            try:
                current.start()
            except NotImplementedError:
                pass
            except CuckooDisableModule:
                continue
            except:
                log.exception(
                    "Unable to start auxiliary module %s",
                    module_name, extra={"task_id": self.task["id"]}
                )
            else:
                log.debug("Started auxiliary module: %s",
                          current.__class__.__name__)
                self.enabled.append(current)

    def callback(self, name, *args, **kwargs):
        def default(*args, **kwargs):
            pass

        enabled = []
        for module in self.enabled:
            try:
                getattr(module, "cb_%s" % name, default)(*args, **kwargs)
            except NotImplementedError:
                pass
            except CuckooDisableModule:
                continue
            except:
                log.exception(
                    "Error performing callback %r on auxiliary module %r",
                    name, module.__class__.__name__,
                    extra={"task_id": self.task["id"]}
                )

            enabled.append(module)
        self.enabled = enabled

    def stop(self):
        for module in self.enabled:
            try:
                module.stop()
            except NotImplementedError:
                pass
            except:
                log.exception(
                    "Unable to stop auxiliary module: %s",
                    module.__class__.__name__,
                    extra={"task_id": self.task["id"]}
                )
            else:
                log.debug("Stopped auxiliary module: %s",
                          module.__class__.__name__)

class RunProcessing(object):
    """Analysis Results Processing Engine.

    This class handles the loading and execution of the processing modules.
    It executes the enabled ones sequentially and generates a dictionary which
    is then passed over the reporting engine.
    """

    def __init__(self, task):
        """@param task: task dictionary of the analysis to process."""
        self.task = task
        self.analysis_path = cwd("storage", "analyses", "%s" % task["id"])
        self.baseline_path = cwd("storage", "baseline")
        self.cfg = Config("processing")

    def process(self, module, results):
        """Run a processing module.
        @param module: processing module to run.
        @param results: results dict.
        @return: results generated by module.
        """
        # Initialize the specified processing module.
        try:
            current = module()
        except:
            log.exception(
                "Failed to load the processing module: %s",
                module, extra={"task_id": self.task["id"]}
            )
            return None, None

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.debug("Processing module %s not found in configuration file",
                      module_name)
            return None, None

        # If the processing module is disabled in the config, skip it.
        if not options.enabled:
            return None, None

        # Give it the path to the baseline directory.
        current.set_baseline(self.baseline_path)
        # Give it the path to the analysis results.
        current.set_path(self.analysis_path)
        # Give it the analysis task object.
        current.set_task(self.task)
        # Give it the options from the relevant processing.conf section.
        current.set_options(options)
        # Give the results that we have obtained so far.
        current.set_results(results)

        try:
            # Run the processing module and retrieve the generated data to be
            # appended to the general results container.
            data = current.run()

            log.debug("Executed processing module \"%s\" on analysis at "
                      "\"%s\"", current.__class__.__name__, self.analysis_path)

            # If succeeded, return they module's key name and the data.
            return current.key, data
        except CuckooDependencyError as e:
            log.warning(
                "The processing module \"%s\" has missing dependencies: %s",
                current.__class__.__name__, e
            )
        except CuckooProcessingError as e:
            log.warning(
                "The processing module \"%s\" returned the following "
                "error: %s",
                current.__class__.__name__, e
            )
        except:
            log.exception(
                "Failed to run the processing module \"%s\" for task #%d:",
                current.__class__.__name__, self.task["id"],
                extra={"task_id": self.task["id"]}
            )

        return None, None

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
        results = {
            "_temp": {},
        }

        # Order modules using the user-defined sequence number.
        # If none is specified for the modules, they are selected in
        # alphabetical order.
        processing_list = cuckoo.processing.plugins

        # If no modules are loaded, return an empty dictionary.
        if processing_list:
            processing_list.sort(key=lambda module: module.order)

            # Run every loaded processing module.
            for module in processing_list:
                key, result = self.process(module, results)

                # If the module provided results, append it to the fat dict.
                if key and result:
                    results[key] = result
        else:
            log.info("No processing modules loaded")

        results.pop("_temp", None)

        # Return the fat dict.
        return results

class RunSignatures(object):
    """Run Signatures."""

    def __init__(self, results):
        self.results = results
        self.matched = []
        self.version = version

        # Gather all enabled, up-to-date, and applicable signatures.
        self.signatures = []
        for signature in cuckoo.signatures:
            if self.should_enable_signature(signature):
                self.signatures.append(signature(self))

        # Sort Signatures by their order.
        self.signatures.sort(key=lambda sig: sig.order)

        # Signatures to call per API name.
        self.api_sigs = {}

    def should_enable_signature(self, signature):
        """Should the given signature be enabled for this analysis?"""
        if not signature.enabled or signature.name is None:
            return False

        if not self.check_signature_version(signature):
            return False

        if hasattr(signature, "enable") and callable(signature.enable):
            if not signature.enable():
                return False

        # Network and/or cross-platform signatures.
        if not signature.platform:
            return True

        task_platform = self.results.get("info", {}).get("platform")

        # Windows is implied when a platform has not been specified during the
        # submission of a sample, but for other platforms the platform has to
        # be explicitly stated.
        if not task_platform and signature.platform == "windows":
            return True

        return task_platform == signature.platform

    def check_signature_version(self, sig):
        """Check signature version.
        @param current: signature class/instance to check.
        @return: check result.
        """
        if not supported_version(self.version, sig.minimum, sig.maximum):
            log.debug(
                "You are running a version of Cuckoo that's not compatible "
                "with this signature (either it's too old or too new): "
                "cuckoo=%s signature=%s minversion=%s maxversion=%s",
                self.version, sig.name, sig.minimum, sig.maximum
            )
            return False

        if hasattr(sig, "run"):
            log.warning(
                "This signatures features one or more deprecated functions "
                "which indicates that it is very likely an old-style "
                "signature. Please upgrade this signature: %s.", sig.name
            )
            return False

        return True

    def call_signature(self, signature, handler, *args, **kwargs):
        """Wrapper to call into 3rd party signatures. This wrapper yields the
        event to the signature and handles matched signatures recursively."""
        try:
            if not signature.matched and handler(*args, **kwargs):
                signature.matched = True
                for sig in self.signatures:
                    self.call_signature(sig, sig.on_signature, signature)
        except NotImplementedError:
            return False
        except:
            task_id = self.results.get("info", {}).get("id")
            log.exception(
                "Failed to run '%s' of the %s signature",
                handler.__name__, signature.name,
                extra={"task_id": task_id}
            )
        return True

    def init_api_sigs(self, apiname, category):
        """Initialize a list of signatures for which we should trigger its
        on_call method for this particular API name and category."""
        self.api_sigs[apiname] = []

        for sig in self.signatures:
            if sig.filter_apinames and apiname not in sig.filter_apinames:
                continue

            if sig.filter_categories and category not in sig.filter_categories:
                continue

            self.api_sigs[apiname].append(sig)

    def yield_calls(self, proc):
        """Yield calls of interest to each interested signature."""
        for idx, call in enumerate(proc.get("calls", [])):

            # Initialize a list of signatures to call for this API call.
            if call["api"] not in self.api_sigs:
                self.init_api_sigs(call["api"], call.get("category"))

            # See the following SO answer on why we're using reversed() here.
            # http://stackoverflow.com/a/10665800
            for sig in reversed(self.api_sigs[call["api"]]):
                sig.cid, sig.call = idx, call
                if self.call_signature(sig, sig.on_call, call, proc) is False:
                    self.api_sigs[call["api"]].remove(sig)

    def run(self):
        """Run signatures."""
        # Allow signatures to initialize themselves.
        for signature in self.signatures:
            signature.init()

        log.debug("Running %d signatures", len(self.signatures))

        # Iterate calls and tell interested signatures about them.
        for proc in self.results.get("behavior", {}).get("processes", []):

            # Yield the new process event.
            for sig in self.signatures:
                sig.pid = proc["pid"]
                self.call_signature(sig, sig.on_process, proc)

            self.yield_calls(proc)

        # Yield completion events to each signature.
        for sig in self.signatures:
            self.call_signature(sig, sig.on_complete)

        score = 0
        for signature in self.signatures:
            if signature.matched:
                log.debug(
                    "Analysis matched signature: %s", signature.name, extra={
                        "action": "signature.match", "status": "success",
                        "signature": signature.name,
                        "severity": signature.severity,
                    }
                )
                self.matched.append(signature.results())
                if "info" in self.results:
                    score += self._context_aware_score(
                                signature, self.results["info"]["package"])
                else:
                    score += signature.severity

        # Sort the matched signatures by their severity level and put them
        # into the results dictionary.
        self.matched.sort(key=lambda key: key["severity"])
        self.results["signatures"] = self.matched
        if "info" in self.results:
            self.results["info"]["score"] = score / 5.0


    #
    # Returns a signature score based on the analysis package.
    # Signature score multipliers are defined per signature.
    #
    def _context_aware_score(self, signature, package):
        ctx = Signature.context_from_package(package)
        if ctx in signature.weights:
            # If provided get the signature-specific multiplier
            multiplier = signature.weights[ctx]
        else:
            # If everything else fails use 1.0
            multiplier = 1.0
        #log.warning("Multiplier set to %.2f", multiplier)

        return signature.severity * multiplier

class RunReporting(object):
    """Reporting Engine.

    This class handles the loading and execution of the enabled reporting
    modules. It receives the analysis results dictionary from the Processing
    Engine and pass it over to the reporting modules before executing them.
    """

    def __init__(self, task, results):
        """@param analysis_path: analysis folder path."""
        self.task = task
        self.results = results
        self.analysis_path = cwd("storage", "analyses", "%s" % task["id"])
        self.cfg = Config("reporting")

    def process(self, module):
        """Run a single reporting module.
        @param module: reporting module.
        @param results: results results from analysis.
        """
        # Initialize current reporting module.
        try:
            current = module()
        except:
            log.exception(
                "Failed to load the reporting module: %s", module,
                extra={"task_id": self.task["id"]}
            )
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

        try:
            current.run(self.results)
            log.debug("Executed reporting module \"%s\"", current.__class__.__name__)
        except CuckooDependencyError as e:
            log.warning(
                "The reporting module \"%s\" has missing dependencies: %s",
                current.__class__.__name__, e
            )
        except CuckooReportError as e:
            log.warning(
                "The reporting module \"%s\" returned the following "
                "error: %s", current.__class__.__name__, e
            )
        except:
            log.exception(
                "Failed to run the reporting module: %s",
                current.__class__.__name__,
                extra={"task_id": self.task["id"]}
            )

    def run(self):
        """Generates all reports.
        @raise CuckooReportError: if a report module fails.
        """
        # In every reporting module you can specify a numeric value that
        # represents at which position that module should be executed among
        # all the available ones. It can be used in the case where a
        # module requires another one to be already executed beforehand.
        reporting_list = cuckoo.reporting.plugins

        # Return if no reporting modules are loaded.
        if reporting_list:
            reporting_list.sort(key=lambda module: module.order)

            # Run every loaded reporting module.
            for module in reporting_list:
                self.process(module)
        else:
            log.info("No reporting modules loaded")
