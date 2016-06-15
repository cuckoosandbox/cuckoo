# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import json
import sys

class Cuckooml(object):
    """Machine Learning for Cuckoo."""
    LABEL_SIGNIFICANCE_COUNT = 5
    POSITIVE_RATE = 2 * LABEL_SIGNIFICANCE_COUNT

    def __init__(self):
        self.report = None
        self.total = None
        self.positives = None
        self.label = None


    def load_json(self, json_path):
        """Load JSON formatted malware report."""
        with open(json_path, "r") as malware_report:
            try:
                self.report = json.load(malware_report)
            except ValueError, error:
                print >> sys.stderr, "Could not load file;", \
                    malware_report, "is not a valid JSON file."
                print >> sys.stderr, "Exception: %s" % str(error)
                sys.exit(1)


    def label_sample(self, label_type="family"):
        """Generate label for the loaded sample.
        You can use platform, cve, metatype, type, and family (default)."""
        # Get total and positives
        self.total = self.report.get("virustotal").get("total")
        self.positives = self.report.get("virustotal").get("positives")

        # Pull all VT normalised results
        vendors = self.report.get("virustotal").get("scans")

        if not vendors:
            self.label = "none"
            return

        aggregated_labels = []
        for vendor in vendors:
            aggregated_labels += self.report["virustotal"]["scans"][vendor]\
                ["normalized"][label_type]

        if not aggregated_labels:
            self.label = "none"
            return

        # Get most common label if it has more hits than set threshold
        print aggregated_labels
        labels_frequency = collections.Counter(aggregated_labels)
        top_label, top_label_count = labels_frequency.most_common(1)[0]
        if top_label_count >= self.LABEL_SIGNIFICANCE_COUNT:
                # self.positives >= self.POSITIVE_RATE:
            self.label = top_label.encode("ascii", "ignore")
        else:
            self.lobel = "none"
