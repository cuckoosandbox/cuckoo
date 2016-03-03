# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import subprocess

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class Screenshots(Processing):
    """Screenshot file OCR analysis."""

    def run(self):
        """Run analysis.
        @return: list of screenshots with OCR content.
        """

        self.key = "screenshots"
        screenshots = []

        tesseract = self.options.get("tesseract", "/usr/bin/tesseract")
        if not os.path.exists(tesseract):
            log.error("Could not find tesseract binary, "
                      "screenshot OCR aborted.")
            return []

        if os.path.exists(self.shots_path):
            # Walk through the files and select the JPGs.
            for shot_file in sorted(os.listdir(self.shots_path)):
                if not shot_file.endswith(".jpg"):
                    continue

                # Get path to the screenshot.
                shot_path = os.path.join(self.shots_path, shot_file)

                # Initialize the entry for the results dict.
                shot_entry = dict(path=shot_path, ocr="")

                try:
                    args = [tesseract, shot_path, "stdout"]
                    shot_entry["ocr"] = subprocess.check_output(args)
                except subprocess.CalledProcessError as e:
                    log.info("Error running tesseract: %s", e)

                # Append entry to list of screenshots.
                screenshots.append(shot_entry)

        return screenshots
