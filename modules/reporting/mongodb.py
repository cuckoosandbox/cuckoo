# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import hashlib

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from lib.cuckoo.common.objects import File

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure, InvalidDocument
    from gridfs import GridFS
    from gridfs.errors import FileExists
except ImportError:
    raise CuckooDependencyError("Unable to import pymongo")

class MongoDB(Report):
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
                pcap_id = self._db.fs.files.find_one({"md5": pcap.get_md5()})[u"_id"]
            # Preventive key check.
            if "network" in results:
                results["network"]["pcap_id"] = pcap_id
            else:
                results["network"] = {"pcap_id": pcap_id}

        # Add dropped files, check for dups and in case add only reference.
        # TODO: refactor the following!! It's temporary.
        if "dropped" in results:
            for dir_name, dir_names, file_names in os.walk(os.path.join(self.analysis_path, "files")):
                for file_name in file_names:
                    file_path = os.path.join(dir_name, file_name)
                    md5 = hashlib.md5(open(file_path, "rb").read()).hexdigest()

                    for dropped in results["dropped"]:
                        if "md5" in dropped and dropped["md5"] == md5:
                            drop_file = os.path.join(file_path)
                            if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
                                try:
                                    drop = open(file_path, 'r')
                                except IOError as e:
                                    raise CuckooReportError("Failed to read file %s: %s" % (file_path, e))
                                try:
                                    drop_id = self._fs.put(drop, filename=dropped["name"])
                                except FileExists:
                                    drop_id = self._db.fs.files.find_one({"md5": dropped["md5"]})[u"_id"]
                                dropped["dropped_id"] = drop_id

        # Add screenshots.
        results["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = [f for f in os.listdir(shots_path) if f.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                try:
                    shot = File(shot_path)
                except IOError as e:
                    raise CuckooReportError("Failed to read screenshot %s: %s" % (shot_path, e))

                try:
                    shot_id = self._fs.put(shot.get_data(), filename=shot.get_name())
                except FileExists:
                    shot_id = self._db.fs.files.find_one({"md5": shot.get_md5()})[u"_id"]
                results["shots"].append(shot_id)

        # Save all remaining results.
        try:
            self._db.analysis.save(results)
        except InvalidDocument:
            # The document is too big, we need to shrink it and re-save it.
            results["behavior"]["processes"] = ""

            # Let's add an error message to the debug block.
            error = ("The analysis results were too big to be stored, " +
                     "the detailed behavioral analysis has been stripped out.")
            results["debug"]["errors"].append(error)

            # Try again to store, if it fails, just abort.
            try:
                self._db.analysis.save(results)
            except Exception as e:
                raise CuckooReportError("Failed to store the document into MongoDB: %s" % e)

    def _connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        if "host" in self.options:
            host = self.options["host"]
        else:
            host = "127.0.0.1"
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
