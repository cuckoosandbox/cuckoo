# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import subprocess
from PIL import Image

from cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class Screenshots(Processing):
    """Screenshot file + OCR analysis."""

    def run(self):
        """Run analysis.
        @return: list of screenshots with optional OCR content.
        """
        self.key = "screenshots"
        screenshots = []
        tesseract = self.options.get("tesseract")

        if not os.path.isdir(self.shots_path):
            return

        if tesseract and not os.path.exists(tesseract):
            log.error("Could not find tesseract binary, "
                      "screenshot OCR aborted.")

        for shot_file in sorted(os.listdir(self.shots_path)):
            if not shot_file.endswith(".jpg"):
                continue

            if "_" in shot_file:
                continue

            shot_path = os.path.join(self.shots_path, shot_file)
            shot_file_name, shot_file_ext = os.path.splitext(shot_file)

            im = Image.open(shot_path)
            im.thumbnail((320, 320), Image.ANTIALIAS)

            shot_file_name_resized = '%s_%s.jpg' % (shot_file_name, "small")
            shot_path_resized = "%s/%s" % (self.shots_path, shot_file_name_resized)

            im.save(shot_path_resized, "JPEG")

            if tesseract:
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
