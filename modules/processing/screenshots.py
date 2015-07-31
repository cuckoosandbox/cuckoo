# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess

from lib.cuckoo.common.abstracts import Processing

class Screenshots(Processing):
    """Screenshot files analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """

        self.key = "screenshots"
        screenshots = []

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
                    # Try to launch tesseract.
                    ocr = subprocess.Popen(["tesseract", shot_path, "stdout"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except OSError:
                    # Tesseract is not installed.
                    pass
                else:
                    shot_entry["ocr"] = ocr.stdout.read()

                # Append entry to list of screenshots.
                screenshots.append(shot_entry)

        return screenshots
