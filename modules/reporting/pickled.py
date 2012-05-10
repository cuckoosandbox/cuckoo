import os
import pickle

from lib.cuckoo.common.abstracts import Report

class Pickled(Report):
    def run(self, results):
        try:
            pickle.dump(results, open(os.path.join(self.reports_path, "report.pickle"), "w"), 2)
        except (pickle.PickleError, IOError), why:
            print "Failed writing pickle report: %s" % why
