import pkgutil

from lib.cuckoo.base.analysis import Analysis
import plugins.processing as modules

class Processor:
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path

    def _populate(self, package):
        prefix = package.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
            if ispkg:
                continue

            __import__(name, globals(), locals(), ["dummy"], -1)

    def run(self):
        results = {}

        self._populate(modules)
        Analysis()

        for module in Analysis.__subclasses__():
            current = module(self.analysis_path)

            try:
                results[current.key] = current.run()
            except NotImplementedError:
                continue
