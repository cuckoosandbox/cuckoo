# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import pkgutil
import sys
import traceback
import urllib
import urllib2
import xmlrpclib

from lib.common.config import Config
from lib.common.hashing import hash_file
from lib.common.results import NetlogHandler, upload_to_host
from lib.core.constants import PATHS
from lib.core.packages import choose_package_class
from lib.core.osx import set_wallclock
from lib.core.host import CuckooHost
from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooDisableModule
from modules import auxiliary

log = logging.getLogger("analyzer")

class Macalyzer(object):
    """Cuckoo OS X analyser.
    """

    log = logging.getLogger()
    target = None

    files_to_upload = []
    uploaded_hashes = []

    def __init__(self, host, configuration=None):
        self.config = configuration
        self.host = host

    def bootstrap(self):
        _create_result_folders()
        _setup_logging()
        self._detect_target()

    def run(self):
        """Run analysis.
        """
        self.bootstrap()

        self.log.debug("Starting analyzer from %s", os.getcwd())
        self.log.debug("Storing results at: %s", PATHS["root"])

        package = self._setup_analysis_package()

        if self.config.clock:
            set_wallclock(self.config.clock)

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue

            # Import the auxiliary module.
            try:
                __import__(name, globals(), locals(), ["dummy"], -1)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module "
                            "\"%s\": %s", name, e)

        # Walk through the available auxiliary modules.
        aux_enabled, aux_avail = [], []
        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            try:
                aux = module(options=self.config.options, analyzer=self)
                aux_avail.append(aux)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented",
                            module.__name__)
            except CuckooDisableModule:
                continue
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s",
                            module.__name__, e)
            else:
                log.debug("Started auxiliary module %s",
                          module.__name__)
                aux_enabled.append(aux)

        self._analysis(package)

        return self._complete()

    def _complete(self):
        for f in self.files_to_upload:
            self._upload_file(f)
        return True

    #
    # Implementation details
    #

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
        kwargs = {"suggestion" : suggestion}
        package_class = choose_package_class(self.config.file_type,
                                             self.config.file_name, **kwargs)
        if not package_class:
            raise Exception("Could not find an appropriate analysis package")
        # Package initialization
        kwargs = {
            "options" : self.config.get_options(),
            "timeout" : self.config.timeout
        }
        return package_class(self.target, self.host, **kwargs)

    def _analysis(self, package):
        package.start()
        self.files_to_upload = package.touched_files

    def _upload_file(self, filepath):
        if not os.path.isfile(filepath):
            return
        # Check whether we've already dumped this file - in that case skip it
        try:
            hashsum = hash_file(hashlib.sha256, filepath)
            if sha256 in self.uploaded_hashes:
                return
        except IOError as e:
            self.log.info("Error dumping file from path \"%s\": %s", filepath, e)
            return
        filename = "%s_%s" % (hashsum[:16], os.path.basename(filepath))
        upload_path = os.path.join("files", filename)

        try:
            upload_to_host(filepath, upload_path)
            self.uploaded_hashes.append(hashsum)
        except IOError as e:
            self.log.error("Unable to upload dropped file at path \"%s\": %s", filepath, e)

def _create_result_folders():
    for _, folder in PATHS.items():
        if os.path.exists(folder):
            continue
        try:
            os.makedirs(folder)
        except OSError:
            pass


def _setup_logging():
    """ Initialize logger. """
    logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    netlog = NetlogHandler()
    netlog.setFormatter(formatter)
    logger.addHandler(netlog)
    logger.setLevel(logging.DEBUG)



if __name__ == "__main__":
    success = False
    error = ""

    try:
        config = Config(cfg="analysis.conf")
        cuckoo = CuckooHost(config.ip, config.port)
        analyzer = Macalyzer(cuckoo, config)
        success = analyzer.run()

    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    except Exception as err:
        error_exc = traceback.format_exc()
        error = str(err)
        if len(analyzer.log.handlers):
            analyzer.log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        try:
            # Establish connection with the agent XMLRPC server.
            server = xmlrpclib.Server("http://127.0.0.1:8000")
            server.complete(success, error, PATHS["root"])
        except Exception as e:
            # new agent
            data = {
                "status": "complete",
                "description": success
            }
            urllib2.urlopen(
                "http://127.0.0.1:8000/status", urllib.urlencode(data)
            )
