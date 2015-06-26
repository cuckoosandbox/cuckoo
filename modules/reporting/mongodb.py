# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import copy

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    from gridfs import GridFS
    from gridfs.errors import FileExists
    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

class MongoDB(Report):
    """Stores report in MongoDB."""

    # Mongo schema version, used for data migration.
    SCHEMA_VERSION = "1"

    def connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        host = self.options.get("host", "127.0.0.1")
        port = self.options.get("port", 27017)
        db = self.options.get("db", "cuckoo")

        try:
            self.conn = MongoClient(host, port)
            self.db = self.conn[db]
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

        existing = self.db.fs.files.find_one({"sha256": file_obj.get_sha256()})

        if existing:
            return existing["_id"]
        else:
            new = self.fs.new_file(filename=filename,
                                   contentType=file_obj.get_content_type(),
                                   sha256=file_obj.get_sha256())
            for chunk in file_obj.get_chunks():
                new.write(chunk)
            try:
                new.close()
            except FileExists:
                to_find = {"sha256": file_obj.get_sha256()}
                return self.db.fs.files.find_one(to_find)["_id"]
            else:
                return new._id

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_MONGO:
            raise CuckooDependencyError("Unable to import pymongo "
                                        "(install with `pip install pymongo`)")

        self.connect()

        # Set mongo schema version.
        # TODO: This is not optimal becuase it run each analysis. Need to run
        # only one time at startup.
        if "cuckoo_schema" in self.db.collection_names():
            if self.db.cuckoo_schema.find_one()["version"] != self.SCHEMA_VERSION:
                CuckooReportError("Mongo schema version not expected, check data migration tool")
        else:
            self.db.cuckoo_schema.save({"version": self.SCHEMA_VERSION})

        # Set an unique index on stored files, to avoid duplicates.
        # From pymongo docs:
        #  Returns the name of the created index if an index is actually
        #    created.
        #  Returns None if the index already exists.
        # TODO: This is not optimal because it run each analysis. Need to run
        # only one time at startup.
        self.db.fs.files.ensure_index("sha256", unique=True,
                                      sparse=True, name="sha256_unique")

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = copy.deepcopy(results)
        if not "network" in report:
            report["network"] = {}

        # Store the sample in GridFS.
        if results["info"]["category"] == "file" and "target" in results:
            sample = File(self.file_path)
            if sample.valid():
                fname = results["target"]["file"]["name"]
                sample_id = self.store_file(sample, filename=fname)
                report["target"] = {"file_id": sample_id}
                report["target"].update(results["target"])

        # Store the PCAP file in GridFS and reference it back in the report.
        pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        pcap = File(pcap_path)
        if pcap.valid():
            pcap_id = self.store_file(pcap)
            report["network"]["pcap_id"] = pcap_id

        sorted_pcap_path = os.path.join(self.analysis_path, "dump_sorted.pcap")
        spcap = File(sorted_pcap_path)
        if spcap.valid():
            spcap_id = self.store_file(spcap)
            report["network"]["sorted_pcap_id"] = spcap_id

        # Store the process memory dump file in GridFS and reference it back in the report.
        if "procmemory" in report and self.options.get("store_memdump", False):
            for idx, procmem in enumerate(report["procmemory"]):
                procmem_path = os.path.join(self.analysis_path, "memory", "{0}.dmp".format(procmem["pid"]))
                procmem_file = File(procmem_path)
                if procmem_file.valid():
                    procmem_id = self.store_file(procmem_file)
                    report["procmemory"][idx].update({"procmem_id": procmem_id})

        # Walk through the dropped files, store them in GridFS and update the
        # report with the ObjectIds.
        new_dropped = []
        if "dropped" in report:
            for dropped in report["dropped"]:
                new_drop = dict(dropped)
                drop = File(dropped["path"])
                if drop.valid():
                    dropped_id = self.store_file(drop, filename=dropped["name"])
                    new_drop["object_id"] = dropped_id

                new_dropped.append(new_drop)

        report["dropped"] = new_dropped

        # Add screenshots.
        report["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            # Walk through the files and select the JPGs.
            shots = [shot for shot in os.listdir(shots_path)
                     if shot.endswith(".jpg")]

            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path,
                                         "shots", shot_file)
                shot = File(shot_path)
                # If the screenshot path is a valid file, store it and
                # reference it back in the report.
                if shot.valid():
                    shot_id = self.store_file(shot)
                    report["shots"].append(shot_id)

        # Store chunks of API calls in a different collection and reference
        # those chunks back in the report. In this way we should defeat the
        # issue with the oversized reports exceeding MongoDB's boundaries.
        # Also allows paging of the reports.
        if "behavior" in report and "processes" in report["behavior"]:
            new_processes = []
            for process in report["behavior"]["processes"]:
                new_process = dict(process)

                chunk = []
                chunks_ids = []
                # Loop on each process call.
                for index, call in enumerate(process["calls"]):
                    # If the chunk size is 100 or if the loop is completed then
                    # store the chunk in MongoDB.
                    if len(chunk) == 100:
                        to_insert = {"pid": process["process_id"],
                                     "calls": chunk}
                        chunk_id = self.db.calls.insert(to_insert)
                        chunks_ids.append(chunk_id)
                        # Reset the chunk.
                        chunk = []

                    # Append call to the chunk.
                    chunk.append(call)

                # Store leftovers.
                if chunk:
                    to_insert = {"pid": process["process_id"], "calls": chunk}
                    chunk_id = self.db.calls.insert(to_insert)
                    chunks_ids.append(chunk_id)

                # Add list of chunks.
                new_process["calls"] = chunks_ids
                new_processes.append(new_process)

            # Store the results in the report.
            report["behavior"] = dict(report["behavior"])
            report["behavior"]["processes"] = new_processes

        # Store the report and retrieve its object id.
        self.db.analysis.save(report)
        self.conn.close()
