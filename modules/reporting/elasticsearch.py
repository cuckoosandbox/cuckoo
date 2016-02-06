# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

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

    def do_index(self, obj):
        index = "%s-%d" % (self.index, self.task["id"])

        try:
            self.es.create(index=index, doc_type=self.type_, body=obj)
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

        self.idx += 1

    def process_behavior(self, results, paginate=100):
        """Index the behavioral data."""
        for process in results.get("behavior", {}).get("processes", []):
            page, calls = 0, []
            for call in process["calls"]:
                calls.append(call)

                if len(calls) == paginate:
                    self.do_index({
                        "process": {
                            "pid": process["pid"],
                            "page": page,
                            "calls": calls,
                        },
                    })

                    page += 1
                    calls = []

            if calls:
                self.do_index({
                    "process": {
                        "pid": process["pid"],
                        "page": page,
                        "calls": calls,
                    },
                })

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
        self.idx = 0

        # Index target information, the behavioral summary, and
        # VirusTotal results.
        self.do_index({
            "target": results.get("target"),
            "summary": results.get("behavior", {}).get("summary"),
            "virustotal": results.get("virustotal"),
        })

        # Index the API calls.
        if self.options.get("calls"):
            self.process_behavior(results)
