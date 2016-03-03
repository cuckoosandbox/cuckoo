# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class Baseline(Processing):
    """Reduces Baseline results from gathered information."""
    order = 2

    def deep_tuple(self, o, bl=None):
        if isinstance(o, (tuple, list)):
            r = []
            for x in o:
                r.append(self.deep_tuple(x))
            return tuple(r)

        if isinstance(o, dict):
            r = []
            for k, v in sorted(o.items()):
                if bl and k in bl:
                    continue
                r.append((k, self.deep_tuple(v)))
            return tuple(r)

        return o

    def normalize(self, plugin, o):
        plugins = {
            "pslist": ["num_threads", "num_handles"],
        }
        return self.deep_tuple(o, plugins.get(plugin))

    def memory(self, baseline, report):
        """Finds the differences between the analysis report and the baseline
        report. Puts the differences into the baseline part of the report and
        also marks the existing rows with a `class_` attribute."""
        results = {}

        for plugin in baseline.keys() + report.keys():
            results[plugin] = {
                "config": {},
                "data": [],
            }

        # TODO Support having more keys in one report than the other.
        for plugin in set(baseline.keys() + report.keys()):
            lr = [self.normalize(plugin, x) for x in report[plugin]["data"]]
            lb = [self.normalize(plugin, x) for x in baseline[plugin]["data"]]
            sr, sb = set(lr), set(lb)

            # Baseline vs Analysis. These events were no longer present
            # after the analysis.
            for row in sb.difference(sr):
                row = baseline[plugin]["data"][lb.index(row)]
                row["class_"] = "warning"
                results[plugin]["data"].append(row)
                report[plugin]["data"].append(row)

            # Analysis vs Baseline. These events were added during
            # the analysis.
            for row in sr.difference(sb):
                row = report[plugin]["data"][lr.index(row)]
                row["class_"] = "danger"
                results[plugin]["data"].append(row)

        return results

    def store_baseline(self, machine, baseline):
        """Store a new baseline report for a particular VM."""
        results = {
            "memory": self.results.get("memory", {}),
        }

        with open(baseline, "wb") as report:
            json.dump(results, report, indent=4, encoding="latin-1")

    def run(self):
        self.key = "baseline"

        machine = self.results.get("info", {}).get("machine", {})
        if not machine or not machine.get("name"):
            log.warning("Unable to run baseline processing module as we did "
                        "not find the name of the Virtual Machine.")
            return

        machine = machine["name"]
        baseline = os.path.join(self.baseline_path, "%s.json" % machine)

        # If this task has the baseline category then we're creating a new
        # baseline report for a VM (and store it right away).
        if self.task["category"] == "baseline":
            self.store_baseline(machine, baseline)
            return

        if not os.path.exists(baseline):
            log.info("Could not find a baseline report for machine '%s', "
                     "skipping it.", machine)
            return

        try:
            self.baseline = json.load(open(baseline, "rb"))
        except Exception as e:
            log.warning("Baseline report for machine '%s' seems corrupted, "
                        "skipping baseline processing: %s.", machine, e)
            return

        results = {}

        if "memory" in self.results:
            results["memory"] = \
                self.memory(self.baseline["memory"], self.results["memory"])

        return results
