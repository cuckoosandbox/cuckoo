import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure
    from gridfs import GridFS
except ImportError:
    raise CuckooDependencyError("Unable to import pymongo")


class MongoDb(Report):
    """
    Save report in MongoDB.
    """
    
    def run(self, results):
        self._connect()
        db = self._conn.cuckoo
        fs = GridFS(db)
        pcap_file = os.path.join(self.analysis_path, "dump.pcap")
        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) != 0:
            pcap = open(pcap_file, 'r')
            pcap_id = fs.put(pcap, filename="dump.pcap")
            if results.has_key("network"):
                results["network"]["pcap_id"] = pcap_id
            else:
                results["network"] = {"pcap_id": pcap_id}

        if results.has_key("dropped"):
            for dropped in results["dropped"]:
                if dropped.has_key("name"):
                    drop_file = os.path.join(self.analysis_path,
                                             "files",
                                             dropped["name"])
                    if os.path.exists(drop_file) and os.path.getsize(drop_file) != 0:
                        drop = open(drop_file, 'r')
                        drop_id = fs.put(drop, filename=dropped["name"])
                        dropped["dropped_id"] = drop_id

        db.analysis.save(results)

    def _connect(self):
        if self.options.has_key("host"):
            host = self.options["host"]
        else:
            host = "localhost"
        if self.options.has_key("port"):
            port = self.options["port"]
        else:
            port = 27017

        try:
            self._conn = Connection(host, port)
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")
