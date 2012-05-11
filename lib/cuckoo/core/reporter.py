import os
import pkgutil
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
import modules.reporting as plugins

log = logging.getLogger(__name__)

class Reporter:
    def __init__(self, analysis_path, custom=""):
        self.analysis_path = analysis_path
        self.custom = custom
        self.__populate(plugins)

    def __populate(self, modules):
        prefix = modules.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(modules.__path__, prefix):
            if ispkg:
                continue

            __import__(name, globals(), locals(), ["dummy"], -1)

    def run(self, results):
        Report()

        for plugin in Report.__subclasses__():
            current = plugin()
            current.set_path(self.analysis_path)

            try:
                current.run(results)
            except NotImplementedError:
                continue
            except CuckooReportError as e:
                log.error(e.message)
