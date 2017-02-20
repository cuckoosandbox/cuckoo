# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cuckoo.common.abstracts import Report
from cuckoo.core.feedback import CuckooFeedbackObject, CuckooFeedback

class Feedback(Report):
    """Reports feedback to the Cuckoo Feedback backend if required."""

    def run(self, results):
        # Nothing to see here.
        if not results.get("debug", {}).get("errors"):
            return

        feedback = CuckooFeedback()
        if not feedback.enabled():
            return

        fo = CuckooFeedbackObject(
            message="One or more errors occurred during an analysis",
            automated=True
        )

        for error in results["debug"]["errors"]:
            fo.add_error(error)

        fo.gather_export_files(self.analysis_path)
        feedback.send_feedback(fo)
