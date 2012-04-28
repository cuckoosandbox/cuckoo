import os
import pkgutil

from lib.cuckoo.base.report import Report
import plugins.reporting as modules

class Reporter:
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path

    def run(self):
        prefix = modules.__name__ = "."
        for loader, name, ispkg in pkgutil.iter_modules(module.__path__, prefix):
            if ispkt:
                continue

            __import__(name, globals(), locals(), ["dummy"], -1)
 
        Report()
        for module in Report.__subclasses__():
            current = module(self.analysis_path)

            try:
                current.run()
            except NotImplementedError:
                continue
