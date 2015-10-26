#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import logging
from sys import stderr
from hashlib import sha256
from xmlrpclib import Server
from traceback import format_exc
from os import path, getcwd, makedirs

from lib.common.config import Config
from lib.common.hashing import hash_file
from lib.common.results import NetlogHandler, upload_to_host
from lib.core.constants import PATHS
from lib.core.packages import choose_package_class
from lib.core.osx import set_wallclock
from lib.core.host import CuckooHost

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

        self.log.debug("Starting analyzer from %s", getcwd())
        self.log.debug("Storing results at: %s", PATHS["root"])

        package = self._setup_analysis_package()

        if self.config.clock:
            set_wallclock(self.config.clock)
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
            self.target = path.join("/tmp/", str(self.config.file_name))
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
        if not path.isfile(filepath):
            return
        # Check whether we've already dumped this file - in that case skip it
        try:
            hashsum = hash_file(sha256, filepath)
            if sha256 in self.uploaded_hashes:
                return
        except IOError as e:
            self.log.info("Error dumping file from path \"%s\": %s", filepath, e)
            return
        filename = "%s_%s" % (hashsum[:16], path.basename(filepath))
        upload_path = path.join("files", filename)

        try:
            upload_to_host(filepath, upload_path)
            self.uploaded_hashes.append(hashsum)
        except IOError as e:
            self.log.error("Unable to upload dropped file at path \"%s\": %s", filepath, e)

def _create_result_folders():
    for _, folder in PATHS.items():
        if path.exists(folder):
            continue
        try:
            makedirs(folder)
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
        error_exc = format_exc()
        error = str(err)
        if len(analyzer.log.handlers):
            analyzer.log.exception(error_exc)
        else:
            stderr.write("{0}\n".format(error_exc))
    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        # Establish connection with the agent XMLRPC server.
        server = Server("http://127.0.0.1:8000")
        server.complete(success, error, PATHS["root"])
