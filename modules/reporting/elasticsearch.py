# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from elasticsearch import (
        Elasticsearch, ConnectionError, ConnectionTimeout
    )
    HAVE_ELASTIC = True
except ImportError:
    HAVE_ELASTIC = False

log = logging.getLogger(__name__)

class ElasticSearchReporting(Report):
    """Stores report in Elasticsearch."""

    def connect(self):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        hosts = []
        for host in self.options.get("hosts", "127.0.0.1:9200").split(","):
            if host.strip():
                hosts.append(host.strip())

        self.index = self.options.get("index", "cuckoo")
        self.type_ = self.options.get("type", "cuckoo")

        try:
            self.es = Elasticsearch(hosts)
        except TypeError:
            raise CuckooReportError(
                "Elasticsearch connection hosts must be host:port or host"
            )
        except (ConnectionError, ConnectionTimeout) as e:
            raise CuckooReportError("Cannot connect to Elasticsearch: %s" % e)

    def run(self, results):
        """Index the Cuckoo report into ElasticSearch.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if the connection or reporting failed.
        """
        if not HAVE_ELASTIC:
            raise CuckooDependencyError(
                "Unable to import elasticsearch (install with "
                "`pip install elasticsearch`)"
            )

        self.connect()

        try:
            self.es.create(index=self.index, doc_type=self.type_,
                           id=self.task["id"], body=results)
        except:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for task #%d" %
                results["info"]["id"]
            )
