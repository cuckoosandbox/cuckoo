# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from lib.cuckoo.common.utils import File

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure
    from gridfs import GridFS
    from gridfs.errors import FileExists
except ImportError:
    raise CuckooDependencyError("Unable to import pymongo")


class MongoDb(Report):
    """Stores report in MongoDB."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        self._connect()

        # Set an unique index on stored files, to avoid duplicates.
        if not self._db.fs.files.ensure_index("md5", unique=True):
            self._db.fs.files.create_index("md5", unique=True, name="md5_unique")

        # Add pcap file, check for dups and in case add only reference.
        pcap_file = os.path.join(self.analysis_path, "dump.pcap")
        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) != 0:
            pcap = File(pcap_file)
            try:
                pcap_id = self._fs.put(pcap.get_data(), filename=pcap.get_name())
            except FileExists:
                pcap_id = self._db.fs.files.find({"md5": pcap.get_md5()})[0][u"_id"]
            # Preventive key check.
            if "network" in results:
                results["network"]["pcap_id"] = pcap_id
            else:
                results["network"] = {"pcap_id": pcap_id}

        # Add dropped files, check for dups and in case add only reference.
        if "dropped" in results:
            for dropped in results["dropped"]:
                if "name" in dropped:
                    drop_file = os.path.join(self.analysis_path,
                                             "files",
                                             dropped["name"])
                    if os.path.exists(drop_file) and os.path.getsize(drop_file) != 0:
                        drop = open(drop_file, 'r')
                        try:
                            drop_id = self._fs.put(drop, filename=dropped["name"])
                        except FileExists as e:
                            drop_id = self._db.fs.files.find({"md5": dropped["md5"]})[0][u"_id"]
                        dropped["dropped_id"] = drop_id

        # Add screenshots.
        results["shots"] = []
        if os.path.exists(os.path.join(self.analysis_path, "shots")):
            shots = [f for f in os.listdir(os.path.join(self.analysis_path, "shots")) if f.endswith(".jpg")]
            for shot_file in shots:
                shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                try:
                    shot = File(shot_path)
                except IOError as e:
                    raise CuckooReportError("Failed to read screenshot %s: %s" % (shot_path, e.message))

                try:
                    shot_id = self._fs.put(shot.get_data(), filename=shot.get_name())
                except FileExists:
                    shot_id = self._db.fs.files.find({"md5": shot.get_md5()})[0][u"_id"]
                results["shots"].append(shot_id)

        # Save all remaining results.
        self._db.analysis.save(results)

    def _connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        if "host" in self.options:
            host = self.options["host"]
        else:
            host = "localhost"
        if "port" in self.options:
            port = self.options["port"]
        else:
            port = 27017

        try:
            self._conn = Connection(host, port)
            self._db = self._conn.cuckoo
            self._fs = GridFS(self._db)
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")
