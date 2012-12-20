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
        # From pymongo docs:
        #  Returns the name of the created index if an index is actually created. 
        #  Returns None if the index already exists.
        self._db.fs.files.ensure_index("md5", unique=True, name="md5_unique")

        # Add pcap file, check for dups and in case add only reference.
        pcap_file = os.path.join(self.analysis_path, "dump.pcap")
        pcap = File(pcap_file)
        if pcap.valid():
            pcap_id = self.store_file(pcap)

            # Preventive key check.
            if "network" in results and isinstance(results["network"], dict):
                results["network"]["pcap_id"] = pcap_id
            else:
                results["network"] = {"pcap_id": pcap_id}

        # Add dropped files, check for dups and in case add only reference.
        dropped_files = {}
        for dir_name, dir_names, file_names in os.walk(os.path.join(self.analysis_path, "files")):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                drop = File(file_path)
                dropped_files[drop.get_md5()] = drop

        result_files = dict((dropped.get("md5", None), dropped) for dropped in results["dropped"])

        # hopefully the md5s in dropped_files and result_files should be the same
        if set(dropped_files.keys()) - set(result_files.keys()):
            log.warning("Dropped files in result dict are different from those in storage.")

        # store files in gridfs
        for md5, fileobj in dropped_files.items():
            # only store in db if we have a filename for it in results (should be all)
            resultsdrop = result_files.get(md5, None)
            if resultsdrop and fileobj.valid():
                drop_id = self.store_file(fileobj, filename=resultsdrop["name"])
                resultsdrop["dropped_id"] = drop_id

        # Add screenshots.
        results["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = [f for f in os.listdir(shots_path) if f.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                shot = File(shot_path)
                if shot.valid():
                    shot_id = self.store_file(shot)
                    results["shots"].append(shot_id)

        # Save all remaining results.
        try:
            self._db.analysis.save(results, manipulate=False)
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

    def store_file(self, fileobj, filename=None):
        if filename == None: filename = fileobj.get_name()

        existing = self._db.fs.files.find_one({"md5": fileobj.get_md5()})
        if not existing:
            gfsfile = self._fs.new_file(filename=filename)
            for chunk in fileobj.get_chunks():
                gfsfile.write(chunk)
            gfsfile.close()

            return gfsfile._id

        return existing["_id"]

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
