import pkgutil

from lib.cuckoo.abstract.analysis import Analysis
import plugins.processing as plugins

class Processor:
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path
        self.__populate(plugins)

    def __populate(self, modules):
        prefix = modules.__name__ + "."
        for loader, name, ispkg in pkgutil.iter_modules(modules.__path__, prefix):
            if ispkg:
                continue

            __import__(name, globals(), locals(), ["dummy"], -1)

    def run(self):
        results = {}
        Analysis()

        for plugin in Analysis.__subclasses__():
            current = plugin()
            current.set_path(self.analysis_path)

            try:
                results[current.key] = current.run()
            except NotImplementedError:
                continue

        return results