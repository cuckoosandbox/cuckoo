# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from lib.cuckoo.common.objects import File

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure, InvalidDocument
    from gridfs import GridFS
except ImportError:
    raise CuckooDependencyError("Unable to import pymongo")

class MongoDB(Report):
    """Stores report in MongoDB."""

    def connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        host = self.options.get("host", "127.0.0.1")
        port = self.options.get("port", 27017)

        try:
            self.conn = Connection(host, port)
            self.db = self.conn.cuckoo
            self.fs = GridFS(self.db)
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")

    def store_file(self, file_obj, filename=""):
        """Store a file in GridFS.
        @param file_obj: object to the file to store
        @param filename: name of the file to store
        @return: object id of the stored file
        """
        if not filename:
            filename = file_obj.get_name()

        existing = self.db.fs.files.find_one({"md5": file_obj.get_md5()})

        if existing:
            return existing["_id"]
        else:
            new = self.fs.new_file(filename=filename)
            for chunk in file_obj.get_chunks():
                new.write(chunk)
            new.close()

            return new._id

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        self.connect()

        report = {}
        report.update(results)

        # Set an unique index on stored files, to avoid duplicates.
        # From pymongo docs:
        #  Returns the name of the created index if an index is actually created. 
        #  Returns None if the index already exists.
        self.db.fs.files.ensure_index("md5", unique=True, name="md5_unique")

        # Add pcap file, check for dups and in case add only reference.
        pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        pcap = File(pcap_path)
        if pcap.valid():
            pcap_id = self.store_file(pcap)

            # Preventive key check.
            if "network" in report and isinstance(report["network"], dict):
                report["network"]["pcap_id"] = pcap_id
            else:
                report["network"] = {"pcap_id": pcap_id}

        # Add dropped files, check for dups and in case add only reference.
        dropped_files = {}
        for dir_name, dir_names, file_names in os.walk(os.path.join(self.analysis_path, "files")):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                drop = File(file_path)
                dropped_files[drop.get_md5()] = drop

        result_files = dict((dropped.get("md5", None), dropped) for dropped in report["dropped"])

        # hopefully the md5s in dropped_files and result_files should be the same
        if set(dropped_files.keys()) - set(result_files.keys()):
            log.warning("Dropped files in result dict are different from those in storage.")

        # store files in gridfs
        for md5, file_obj in dropped_files.items():
            # only store in db if we have a filename for it in results (should be all)
            resultsdrop = result_files.get(md5, None)
            if resultsdrop and file_obj.valid():
                drop_id = self.store_file(file_obj, filename=resultsdrop["name"])
                resultsdrop["dropped_id"] = drop_id

        # Add screenshots.
        report["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = [f for f in os.listdir(shots_path) if f.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                shot = File(shot_path)
                if shot.valid():
                    shot_id = self.store_file(shot)
                    report["shots"].append(shot_id)

        for process in report["behavior"]["processes"]:
            chunk = []
            chunks_ids = []
            # Loop on each process call.
            for index, call in enumerate(process["calls"]):
                # If the chunk size is 100 or if the loop is completed then
                # store the chunk in MongoDB.
                if len(chunk) == 100:
                    chunk_id = self.db.calls.insert({"pid" : process["process_id"],
                                                     "calls" : chunk})
                    chunks_ids.append(chunk_id)
                    # Reset the chunk.
                    chunk = []

                # Append call to the chunk.
                chunk.append(call)

            # Store leftovers.
            if chunk:
                chunk_id = self.db.calls.insert({"pid" : process["process_id"],
                                                 "calls" : chunk})
                chunks_ids.append(chunk_id)

            # Add list of chunks.
            process["calls"] = chunks_ids

        # Store the report and retrieve its object id.
        self.db.analysis.insert(report)
