#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system, chmod
import logging
from subprocess import check_output
from lib.core.packages import Package, choose_package_class


log = logging.getLogger(__name__)


def _fileinfo(target):
    raw = check_output(["file", target])
    # The utility has the following output format: "%filename%: %description%",
    # so we just skip everything before the actual description
    return raw[raw.index(":")+2:]

class Wget(Package):
    """ Mach-O executable analysys package. """

    def prepare(self):
        # todo use random tempfile
        ret = system("wget \"%s\" -O /tmp/file_malwr --no-check-certificate" % self.target)
        log.info(ret)
        chmod("/tmp/file_malwr", 0o755)
        self.target = "/tmp/file_malwr"
        #self.args = [self.target] + self.args
        #self.target = "sh -c"
        file_info = _fileinfo(self.target)
        pkg_class = choose_package_class(file_info)
        kwargs = {
            "options" : self.options,
            "timeout" : self.timeout
        }
        self.real_package = pkg_class(self.target, **kwargs)


    def start(self):
        # We have nothing to do here; let the proper package do it's job
        log.info("Wget v0.02")
        self.prepare()
        if not self.real_package:
            raise Exception("Invalid analysis package, aborting")
        self.real_package.start()
