from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File
import os
import logging
import traceback
log = logging.getLogger(__name__)

class ApiScoutRunner(Processing):

    def run(self):
        self.key = "apiscout"

        # Processing the memory dumps can take a little while. Only proceed if
        # the user has selected the 'procmemdump' option for this task
        # I didn't expect memory dumps to be generated without this option, but for some reason they still are
        if not self.task.get("options", {}).get("procmemdump"):
            raise CuckooProcessingError("procmemdump not set for this task")

        # Get the path to the relevant apiscout DB and make sure it exists
        self.apiscout_db_path = os.path.join(self.options.get("db_paths"), self.machine.get("name","") + ".json")

        if not os.path.exists(self.apiscout_db_path):
            raise CuckooProcessingError("Can't find ApiScout DB file: %s" % self.apiscout_db_path)

        log.info("Using DB %s" % self.apiscout_db_path)

        ret_data = {}
        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                if not dmp.endswith(".dmp"):
                    continue

                dump_path = os.path.join(self.pmemory_path, dmp)
                dump_file = File(dump_path)

                try:
                    log.info("Working on %s" % dmp)
                    vector = self.extract_vector(open(dump_path, "rb").read(), self.apiscout_db_path)
                except:
                    log.exception("Error getting apivector for %s. Traceback: %s" % (dmp, traceback.format_exc()))
                    continue

                ret_data[dmp] = {
                    "sha256": dump_file.get_sha256(),
                    "vector": vector
                }

        return ret_data

    # Copied from https://gitlab.com/GeekWeekV/4.2_malfinder/alsvc_apivector/blob/master/apivector.py
    def extract_vector(self, memory_dump, apiscout_profile_path):
        # Make sure we can import apiscout
        try:
            from apiscout.ApiScout import ApiScout
            import apiscout
        except ImportError as e:
            raise CuckooProcessingError("Unable to import apiscout module")

        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        winapi1024_path = os.sep.join([module_path, "data", "winapi1024v1.txt"])

        scout = ApiScout()
        scout.loadDbFile(apiscout_profile_path)
        # TODO depends on setup that produces memory dumps
        scout.ignoreAslrOffsets(True)
        # TODO potentially change this path
        scout.loadWinApi1024(winapi1024_path)
        results = scout.crawl(memory_dump)
        # experience tells that neighborhood filter of 32 produces good results
        filtered_results = scout.filter(results, 0, 0, 32)
        all_vectors = scout.getWinApi1024Vectors(filtered_results)
        primary_vector = scout.getPrimaryVector(all_vectors)
        return primary_vector
