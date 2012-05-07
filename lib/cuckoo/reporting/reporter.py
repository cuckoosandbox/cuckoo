import os
import pkgutil

from lib.cuckoo.abstract.report import Report
import plugins.reporting as plugins

class Reporter:
    def __init__(self, analysis_path,):
        self.analysis_path = analysis_path
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
