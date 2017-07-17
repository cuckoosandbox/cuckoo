# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gridfs
import logging
import pymongo
import socket

from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError

log = logging.getLogger(__name__)

class Mongo(object):
    def __init__(self):
        self.client = None
        self.db = None

        self.enabled = None
        self.hostname = None
        self.port = None
        self.database = None
        self.username = None
        self.password = None
        self.grid = None

    def init(self):
        self.enabled = config("reporting:mongodb:enabled")
        self.hostname = config("reporting:mongodb:host")
        self.port = config("reporting:mongodb:port")
        self.database = config("reporting:mongodb:db")
        self.username = config("reporting:mongodb:username")
        self.password = config("reporting:mongodb:password")
        return self.enabled

    def connect(self):
        if not self.enabled:
            return

        # Warn the user that this may take a while if an instant connection
        # could not be made with the MongoDB server.
        try:
            socket.create_connection((self.hostname, self.port), 1).close()
        except socket.error:
            log.warning(
                "We're attempting to connect to MongoDB, but the connection "
                "seems slow or MongoDB is simply offline. Please wait while "
                "Cuckoo tries to connect.."
            )

        try:
            self.client = pymongo.MongoClient(self.hostname, self.port)
            self.db = self.client[self.database]
            if self.username and self.password:
                self.db.authenticate(self.username, self.password)
            self.grid = gridfs.GridFS(self.db)

            # Fetch the collection names to force Mongo to connect.
            self.collection_names = self.db.collection_names()
        except pymongo.errors.PyMongoError as e:
            raise CuckooCriticalError(
                "Unable to connect to MongoDB: %s. In order to operate "
                "Cuckoo as per your configuration, a running MongoDB server "
                "is required." % e
            )

mongo = Mongo()
