import pkgutil

from lib.cuckoo.common.abstracts import Analysis, Signature
import plugins.processing as plugins
import plugins.signatures as signatures

class Processor:
    def __init__(self, analysis_path):
        self.analysis_path = analysis_path
        self.__populate(plugins)
        self.__populate(signatures)

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

        Signature()
        sigs = []

        for sig_class in Signature.__subclasses__():
            sig_current = sig_class()
            if not sig_current.enabled:
                continue

            try:
                if sig_current.run(results):
                    sig_matched = {"name" : sig_current.name,
                                   "description" : sig_current.description,
                                   "severity" : sig_current.severity,
                                   "references" : sig_current.references,
                                   "data" : sig_current.data,
                                   "alert" : sig_current.alert}
                    sigs.append(sig_matched)
            except NotImplementedError:
                continue

        results["signatures"] = sigs

        return results
