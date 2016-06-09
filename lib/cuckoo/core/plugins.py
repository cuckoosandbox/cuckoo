# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pkgutil
import importlib
import inspect
import logging
from collections import defaultdict
from distutils.version import StrictVersion

from lib.cuckoo.common.abstracts import Auxiliary, Machinery, LibVirtMachinery, Processing
from lib.cuckoo.common.abstracts import Report, Signature
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooDisableModule

log = logging.getLogger(__name__)

_modules = defaultdict(list)

def enumerate_plugins(dirpath, module_prefix, namespace, class_,
                      attributes={}):
    """Import plugins of type `class` located at `dirpath` into the
    `namespace` that starts with `module_prefix`. If `dirpath` represents a
    filepath then it is converted into its containing directory. The
    `attributes` dictionary allows one to set extra fields for all imported
    plugins."""
    if os.path.isfile(dirpath):
        dirpath = os.path.dirname(dirpath)

    for fname in os.listdir(dirpath):
        if fname.endswith(".py") and not fname.startswith("__init__"):
            module_name, _ = os.path.splitext(fname)
            importlib.import_module("%s.%s" % (module_prefix, module_name))

    plugins = []
    for subclass in class_.__subclasses__():
        # Check whether this subclass belongs to the module namespace that
        # we're currently importing. It should be noted that parent and child
        # namespaces should fail the following if-statement.
        if module_prefix != ".".join(subclass.__module__.split(".")[:-1]):
            continue

        namespace[subclass.__name__] = subclass
        for key, value in attributes.items():
            setattr(subclass, key, value)
        plugins.append(subclass)
    return plugins

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
        import_plugin(name)

def load_plugins(module):
    for name, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, Auxiliary) and value is not Auxiliary:
                register_plugin("auxiliary", value)
            elif issubclass(value, Machinery) and value is not Machinery and value is not LibVirtMachinery:
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

    def __init__(self, task, machine, guest_manager):
        self.task = task
        self.machine = machine
        self.guest_manager = guest_manager

        self.cfg = Config("auxiliary")
        self.enabled = []

    def start(self):
        for module in list_plugins(group="auxiliary"):
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
            current.set_guest_manager(self.guest_manager)
            current.set_options(options)

            try:
                current.start()
            except NotImplementedError:
                pass
            except CuckooDisableModule:
                continue
            except Exception as e:
                log.warning("Unable to start auxiliary module %s: %s",
                            module_name, e)
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
            except Exception as e:
                log.warning(
                    "Error performing callback %r on auxiliary module %r: %s",
                    name, module.__class__.__name__, e
                )

            enabled.append(module)
        self.enabled = enabled

    def stop(self):
        for module in self.enabled:
            try:
                module.stop()
            except NotImplementedError:
                pass
            except Exception as e:
                log.warning("Unable to stop auxiliary module: %s", e)
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
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))
        self.baseline_path = os.path.join(CUCKOO_ROOT, "storage", "baseline")
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
            log.exception("Failed to load the processing module "
                          "\"{0}\":".format(module))
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
            log.warning("The processing module \"%s\" has missing dependencies: %s", current.__class__.__name__, e)
        except CuckooProcessingError as e:
            log.warning("The processing module \"%s\" returned the following "
                        "error: %s", current.__class__.__name__, e)
        except:
            log.exception("Failed to run the processing module \"%s\" for task #%d:",
                          current.__class__.__name__, self.task["id"])

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
        processing_list = list_plugins(group="processing")

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

        # While developing our version is generally something along the lines
        # of "2.0-dev" whereas StrictVersion() does not handle "-dev", so we
        # strip that part off.
        self.version = CUCKOO_VERSION.split("-")[0]

        # Gather all enabled, up-to-date, and applicable signatures.
        self.signatures = []
        for signature in list_plugins(group="signatures"):
            if self._should_enable_signature(signature):
                self.signatures.append(signature(self))

        # Signatures to call per API name.
        self.api_sigs = {}

    def _should_enable_signature(self, signature):
        """Should the given signature be enabled for this analysis?"""
        if not signature.enabled:
            return False

        if not self.check_signature_version(signature):
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

    def check_signature_version(self, signature):
        """Check signature version.
        @param current: signature class/instance to check.
        @return: check result.
        """
        # Check the minimum Cuckoo version for this signature, if provided.
        if signature.minimum:
            try:
                # If the running Cuckoo is older than the required minimum
                # version, skip this signature.
                if StrictVersion(self.version) < StrictVersion(signature.minimum):
                    log.debug("You are running an older incompatible version "
                              "of Cuckoo, the signature \"%s\" requires "
                              "minimum version %s.",
                              signature.name, signature.minimum)
                    return False

                if StrictVersion("1.2") > StrictVersion(signature.minimum):
                    log.warn("Cuckoo signature style has been redesigned in "
                             "cuckoo 1.2. This signature is not "
                             "compatible: %s.", signature.name)
                    return False

                if StrictVersion("2.0") > StrictVersion(signature.minimum):
                    log.warn("Cuckoo version 2.0 features a lot of changes that "
                             "render old signatures ineffective as they are not "
                             "backwards-compatible. Please upgrade this "
                             "signature: %s.", signature.name)
                    return False

                if hasattr(signature, "run"):
                    log.warn("This signatures features one or more deprecated "
                             "functions which indicates that it is very likely "
                             "an old-style signature. Please upgrade this "
                             "signature: %s.", signature.name)
                    return False

            except ValueError:
                log.debug("Wrong minor version number in signature %s",
                          signature.name)
                return False

        # Check the maximum version of Cuckoo for this signature, if provided.
        if signature.maximum:
            try:
                # If the running Cuckoo is newer than the required maximum
                # version, skip this signature.
                if StrictVersion(self.version) > StrictVersion(signature.maximum):
                    log.debug("You are running a newer incompatible version "
                              "of Cuckoo, the signature \"%s\" requires "
                              "maximum version %s.",
                              signature.name, signature.maximum)
                    return False
            except ValueError:
                log.debug("Wrong major version number in signature %s",
                          signature.name)
                return False

        return True

    def call_signature(self, signature, handler, *args, **kwargs):
        """Wrapper to call into 3rd party signatures. This wrapper yields the
        event to the signature and handles matched signatures recursively."""
        try:
            if handler(*args, **kwargs):
                signature.matched = True
                for sig in self.signatures:
                    self.call_signature(sig, sig.on_signature, signature)
        except NotImplementedError:
            return False
        except:
            log.exception("Failed to run '%s' of the %s signature",
                          handler.__name__, signature.name)
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
                log.debug("Analysis matched signature: %s", signature.name)
                self.matched.append(signature.results())
                score += signature.severity

        # Sort the matched signatures by their severity level and put them
        # into the results dictionary.
        self.matched.sort(key=lambda key: key["severity"])
        self.results["signatures"] = self.matched
        if "info" in self.results:
            self.results["info"]["score"] = score / 5.0

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
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))
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
        current.cfg = Config(cfg=current.conf_path)

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
