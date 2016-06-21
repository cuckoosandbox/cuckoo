# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

from datetime import datetime
import json
import logging
import time
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
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


class ElasticSearch(Report):
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

    def apply_template(self):
        template_path = os.path.join(CUCKOO_ROOT, "data", "elasticsearch", "template.json")
        if not os.path.exists(template_path):
            return False
        with open(os.path.join(CUCKOO_ROOT, "data", "elasticsearch", "template.json"), "rw") as f:
            try:
                cuckoo_template = json.loads(f.read())
            except ValueError:
                CuckooReportError("Unable to read valid JSON from the elasticsearch template JSON file located: %s"
                                  % template_path)

        self.es.indices.put_template(name="cuckoo_template", body=json.dumps(cuckoo_template))

    def do_index(self, obj):
        # Set index to cuckoo-YYYY-MM-DD
        strf_time = "%Y-%m-%d"
        date_index = datetime.utcnow().strftime(strf_time)
        index = "%s-%s" % (self.index, date_index)

        # Add task_id to the base of the document
        obj["task_id"] = self.task["id"]

        # Add report time to the base of the document ES needs epoch time in seconds per the mapping
        obj["report_time"] = int(time.time())

        # check to see if the template exists apply it if it does not
        if not self.es.indices.exists_template("cuckoo_template"):
            if not self.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

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
