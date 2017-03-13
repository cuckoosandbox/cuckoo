# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import datetime
import elasticsearch
import json
import logging
import time
import os

from cuckoo.common.abstracts import Report
from cuckoo.common.elastic import elastic
from cuckoo.common.exceptions import CuckooReportError, CuckooOperationalError
from cuckoo.common.utils import convert_to_printable
from cuckoo.misc import cwd

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

log = logging.getLogger(__name__)

class ElasticSearch(Report):
    """Stores report in Elasticsearch."""

    @classmethod
    def init_once(cls):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        # Do not change these types without changing the elasticsearch
        # template as well.
        cls.report_type = "cuckoo"
        cls.call_type = "call"

        if not elastic.init():
            return

        try:
            elastic.connect()
            cls.es = elastic.client
        except CuckooOperationalError as e:
            raise CuckooReportError(
                "Error running ElasticSearch reporting module: %s" % e
            )

        # check to see if the template exists apply it if it does not
        if not cls.es.indices.exists_template("cuckoo_template"):
            if not cls.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

    def apply_template(self):
        template_path = cwd("elasticsearch", "template.json")
        if not os.path.exists(template_path):
            return False

        with open(template_path, "rw") as f:
            try:
                cuckoo_template = json.loads(f.read())
            except ValueError:
                raise CuckooReportError(
                    "Unable to read valid JSON from the ElasticSearch "
                    "template JSON file located at: %s" % template_path
                )

            # Create an index wildcard based off of the index name specified
            # in the config file, this overwrites the settings in
            # template.json.
            cuckoo_template["template"] = elastic.index + "-*"

        self.es.indices.put_template(
            name="cuckoo_template", body=json.dumps(cuckoo_template)
        )
        return True

    def get_base_document(self):
        # Gets precached report time and the task_id.
        header = {
            "task_id": self.task["id"],
            "report_time": self.report_time,
            "report_id": self.task["id"]
        }
        return header

    def do_index(self, obj):
        base_document = self.get_base_document()

        # Append the base document to the object to index.
        base_document.update(obj)

        try:
            self.es.index(
                index=self.dated_index,
                doc_type=self.report_type,
                body=base_document
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def do_bulk_index(self, bulk_reqs):
        try:
            elasticsearch.helpers.bulk(self.es, bulk_reqs)
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def process_call(self, call):
        """This function converts all arguments to strings to allow ES to map
        them properly."""
        if "arguments" not in call or type(call["arguments"]) != dict:
            return call

        new_arguments = {}
        for key, value in call["arguments"].iteritems():
            if type(value) is unicode or type(value) is str:
                new_arguments[key] = convert_to_printable(value)
            else:
                new_arguments[key] = str(value)

        call["arguments"] = new_arguments
        return call

    def process_behavior(self, results, bulk_submit_size=1000):
        """Index the behavioral data."""
        for process in results.get("behavior", {}).get("processes", []):
            bulk_index = []

            for call in process["calls"]:
                base_document = self.get_base_document()
                call_document = {
                    "pid": process["pid"],
                }
                call_document.update(self.process_call(call))
                call_document.update(base_document)
                bulk_index.append({
                    "_index": self.dated_index,
                    "_type": self.call_type,
                    "_source": call_document
                })
                if len(bulk_index) == bulk_submit_size:
                    self.do_bulk_index(bulk_index)
                    bulk_index = []

            if len(bulk_index) > 0:
                self.do_bulk_index(bulk_index)

    def run(self, results):
        """Index the Cuckoo report into ElasticSearch.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if the connection or reporting failed.
        """
        # Gets the time which will be used for indexing the document into ES
        # ES needs epoch time in seconds per the mapping
        self.report_time = int(time.time())

        # Get the index time option and set the dated index accordingly
        date_index = datetime.datetime.utcnow().strftime({
            "yearly": "%Y",
            "monthly": "%Y-%m",
            "daily": "%Y-%m-%d",
        }[elastic.index_time_pattern])
        self.dated_index = "%s-%s" % (elastic.index, date_index)

        # Index target information, the behavioral summary, and
        # VirusTotal results.
        self.do_index({
            "cuckoo_node": elastic.cuckoo_node,
            "target": results.get("target"),
            "summary": results.get("behavior", {}).get("summary"),
            "virustotal": results.get("virustotal"),
            "irma": results.get("irma"),
            "signatures": results.get("signatures"),
            "dropped": results.get("dropped"),
        })

        # Index the API calls.
        if elastic.calls:
            self.process_behavior(results)
