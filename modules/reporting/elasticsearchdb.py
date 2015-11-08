# Cuckoobox to ELK

# -*- coding: utf-8 -*-

import datetime
import copy
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from elasticsearch import Elasticsearch
    from elasticsearch import ConnectionError
    from elasticsearch import ConnectionTimeout
    HAVE_ELK = True
except ImportError:
    HAVE_ELK = False


log = logging.getLogger(__name__)


class ElasticsearchDB(Report):
    """Stores report in Elasticsearch."""

    def walk_dict(self, d, k=None, dk=None):
        if type(d) == type({}):
            for k in d:
                self.walk_dict(k=k, dk=d, d=d[k])
        else:
            if k:
                if isinstance(dk[k], str):
                    try:
                        dk[k] = unicode(dk[k], errors='ignore').encode(
                            encoding='UTF-8')
                    except:
                        log.exception("Except in instance str")
                        dk[k] = ''

                elif isinstance(dk[k], unicode):
                    try:
                        dk[k] = dk[k].encode(encoding='UTF-8')
                    except:
                        log.exception("Except in instance unicode")
                        dk[k] = ''
                else:
                    pass

    def connect(self):
        """Connects to Elasticsearch, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        hosts = self.options.get("hosts", "127.0.0.1:9200").split(",")
        log.info("Elasticsearch hosts: {}".format(hosts))
        index = self.options.get("index", "cuckoobox")
        log.info("Elasticsearch index: {}".format(index))
        doc_type = self.options.get("doc_type", "cuckoo_type")
        log.info("Elasticsearch doc_type: {}".format(doc_type))
        elk_timeout = self.options.get("timeout", "10")
        log.info("Elasticsearch create timeout: {} s".format(elk_timeout))

        try:
            self.es = Elasticsearch(hosts)
            self.index = index
            self.doc_type = doc_type
            self.elk_timeout = elk_timeout
        except TypeError:
            raise CuckooReportError("Elasticsearch connection hosts must be host:port or host")
        except ConnectionError:
            raise CuckooReportError("Cannot connect to Elasticsearch (ConnectionError)")
        except ConnectionTimeout:
            raise CuckooReportError("Cannot connect to Elasticsearch (ConnectionTimeout)")

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELK:
            log.debug("HAVE_ELK: {}".format(HAVE_ELK))
            raise CuckooDependencyError("Unable to import elasticsearch "
                                        "(install with `pip install elasticsearch`)")

        self.connect()

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        body = copy.deepcopy(results)

        log.info("Start Cuckoobox Elasticsearch reporting for task id '{}'".format(results["info"]["id"]))

        try:
            # tags ELK
            body["tags"] = list()

            # Timestamps from string to datetime
            timestamp = datetime.datetime.strptime(results["info"]["started"], "%Y-%m-%d %X")
            body["@timestamp"] = timestamp
            self.index = "{}{}".format(self.index, timestamp.strftime("-%Y.%m.%d"))

            body["info"]["started"] = datetime.datetime.strptime(results["info"]["started"], "%Y-%m-%d %X")
            body["info"]["ended"] = datetime.datetime.strptime(results["info"]["ended"], "%Y-%m-%d %X")
            body["info"]["machine"]["shutdown_on"] = datetime.datetime.strptime(results["info"]["machine"]["shutdown_on"], "%Y-%m-%d %X")
            body["info"]["machine"]["started_on"] = datetime.datetime.strptime(results["info"]["machine"]["started_on"], "%Y-%m-%d %X")

            if body.get("network", {}):
                body["tags"].append("network")

            if body.get("signatures", []):
                body["tags"].append("signatures")
                # @todo: signatures.data.signs.value can be string or dict. In ELK is not
                # possible. A fix can be choose a standard for this field.
                for s in body["signatures"]:
                    s.pop("data")

            if body.get("behavior", {}):
                if body.get("behavior").get("processes", []):
                    body["tags"].append("behavior")
                    for p in body["behavior"]["processes"]:
                        # bson calls are not serializable in ELK (SerializationError)
                        p.pop("calls")
                body["behavior"] = dict(body["behavior"])

            if body.get("static", {}):
                body["tags"].append("static")
                body["static"]["pe_timestamp"] = datetime.datetime.strptime(results["static"]["pe_timestamp"], "%Y-%m-%d %X")

            if body.get("virustotal", {}):
                if body.get("virustotal").get("scan_date", None):
                    body["virustotal"]["scan_date"] = datetime.datetime.strptime(results["virustotal"]["scan_date"], "%Y-%m-%d %X")
                    body["tags"].append("virustotal")

            # Array of virus scans
            new_scans = list()
            if body.get("virustotal", {}):
                if body.get("virustotal").get("scans", {}):
                    for k, v in body.get("virustotal").get("scans").iteritems():
                        if v["detected"] == True:
                            v["antivirus"] = k
                            new_scans.append(v)
                    body["virustotal"]["scans"] = new_scans

            if body.get("infostealers", {}):
                body["tags"].append("infostealers")

        except:
            log.exception("Failed copy results processing for task id '{}'".format(results["info"]["id"]))
            raise CuckooReportError("Failed copy results processing for task id '{}'".format(results["info"]["id"]))

        # Store the report
        try:
            self.walk_dict(d=body)
            self.es.create(index=self.index, doc_type=self.doc_type, body=body, timeout=self.elk_timeout)
        except:
            log.exception("Failed save results in Elasticsearch for task id '{}'".format(results["info"]["id"]))
            raise CuckooReportError("Failed save results in Elasticsearch for task id '{}'".format(results["info"]["id"]))
