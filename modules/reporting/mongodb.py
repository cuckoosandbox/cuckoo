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
            if results.has_key("network"):
                results["network"]["pcap_id"] = pcap_id
            else:
                results["network"] = {"pcap_id": pcap_id}
        # Add dropped files, check for dups and in case add only reference.
        if results.has_key("dropped"):
            for dropped in results["dropped"]:
                if dropped.has_key("name"):
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
        # Save all remaining results.
        self._db.analysis.save(results)

    def _connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
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
            self._db = self._conn.cuckoo
            self._fs = GridFS(self._db)
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")
